#!/usr/bin/env node
/**
 * Regenerates every Atomic icon and favicon from the source marks in
 * `brand/src/`. Those SVGs are the single source of truth; everything this
 * script writes is a derived artifact and should never be hand-edited.
 *
 *   node brand/generate.mjs
 *
 * Outputs are committed to the repo, so app builds and offline checkouts
 * never need rsvg/ImageMagick — only regenerating does.
 *
 * There is no --check mode on purpose. Rendering is deterministic, so `git
 * diff` after a run already answers "has anything drifted?" exactly, using
 * the byte-differ we already have. A CI equivalent would have to compare
 * images perceptually, because librsvg and ImageMagick do not encode
 * identical bytes across versions — which cost far more machinery than the
 * problem (a cosmetically stale icon) was worth.
 *
 * Requires rsvg-convert and ImageMagick 7 (`brew install librsvg
 * imagemagick`). The .icns additionally needs macOS iconutil; off macOS that
 * one target is skipped with a warning rather than failing the run.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BRAND_DIR = path.dirname(fileURLToPath(import.meta.url));
const SERVER_ROOT = path.resolve(BRAND_DIR, '..');
const DEV_ROOT = path.resolve(SERVER_ROOT, '..');

/**
 * Sibling repo. Absent checkouts are skipped rather than failing the run.
 *
 * The marketing site lives inside atomic-saas, next to the portal, because
 * the site's *content* already does — see the reasoning at the top of
 * atomic-saas/portal/scripts/seed-marketing-site.ts. It used to sit in a
 * loose ../atomicserver-site directory that was in no git repo at all, so
 * anything written there was untracked.
 */
const SAAS_ROOT = path.join(DEV_ROOT, 'atomic-saas');

const MARKS = {
  atomic: path.join(BRAND_DIR, 'src', 'atomic-mark.svg'),
  atomicMono: path.join(BRAND_DIR, 'src', 'atomic-mark-mono.svg'),
  canvas: path.join(BRAND_DIR, 'src', 'canvas-mark.svg'),
};

/* ------------------------------------------------------------------ */
/* Rendering primitives                                                */
/* ------------------------------------------------------------------ */

/**
 * Variants:
 *   'alpha'    — transparent background. Web favicons, Windows, Android.
 *   'flat'     — composited on white, alpha stripped. iOS rejects icons
 *                with an alpha channel at App Store submission.
 *   'maskable' — opaque, mark shrunk to 62% so it clears the Android
 *                maskable safe zone (the centre 80%-diameter circle).
 */
function render(markPath, size, variant, outPath) {
  // `size` is a side length, or [w, h] for the one non-square target
  // (the wide Windows tile), where the square mark gets letterboxed.
  const [w, h] = Array.isArray(size) ? size : [size, size];
  const box = Math.min(w, h);
  const inner = variant === 'maskable' ? Math.round(box * 0.62) : box;
  const raw = path.join(TMP, `raw-${path.basename(outPath)}-${w}x${h}-${variant}.png`);

  execFileSync('rsvg-convert', ['-w', String(inner), '-h', String(inner), markPath, '-o', raw]);

  if (variant === 'alpha' && inner === w && inner === h) {
    copyFileSync(raw, outPath);
    return;
  }

  // Transparent padding for tiles, which take their colour from
  // browserconfig.xml's <TileColor>; white only where alpha is dropped.
  const args = ['-background', variant === 'alpha' ? 'none' : 'white'];
  if (variant === 'maskable' || inner !== w || inner !== h) {
    args.push(raw, '-gravity', 'center', '-extent', `${w}x${h}`);
  } else {
    args.push(raw, '-flatten');
  }
  // -alpha off is what actually drops the channel; -flatten alone keeps it.
  // Only for opaque variants — a letterboxed 'alpha' tile must stay transparent.
  if (variant !== 'alpha') args.push('-alpha', 'off');
  // -strip drops the encoder's timestamp, so re-running produces the same
  // bytes on one machine and diffs stay empty when nothing actually changed.
  args.push(...STRIP, outPath);
  execFileSync('magick', args);
}

/** ImageMagick stamps PNGs with a creation date unless told not to. */
const STRIP = ['-strip', '-define', 'png:exclude-chunk=date,time'];

function renderSvg(markPath, outPath) {
  const svg = readFileSync(markPath, 'utf8');
  writeFileSync(
    outPath,
    `<!-- GENERATED from brand/src/${path.basename(markPath)} — do not edit. Run \`node brand/generate.mjs\`. -->\n` +
      svg.replace(/^<!--[\s\S]*?-->\n/, ''),
  );
}

function renderIco(markPath, outPath) {
  const sizes = [16, 32, 48, 64, 128, 256];
  const parts = sizes.map(s => {
    const p = path.join(TMP, `ico-${s}.png`);
    execFileSync('rsvg-convert', ['-w', String(s), '-h', String(s), markPath, '-o', p]);
    return p;
  });
  execFileSync('magick', [...parts, ...STRIP, outPath]);
}

function renderIcns(markPath, outPath) {
  // Unique per call — iconutil takes the whole directory, so a leftover
  // file from an earlier call would silently end up in the bundle.
  const iconset = path.join(TMP, `${path.basename(outPath)}.iconset`);
  rmSync(iconset, { recursive: true, force: true });
  mkdirSync(iconset, { recursive: true });
  const spec = [
    [16, 'icon_16x16.png'], [32, 'icon_16x16@2x.png'],
    [32, 'icon_32x32.png'], [64, 'icon_32x32@2x.png'],
    [128, 'icon_128x128.png'], [256, 'icon_128x128@2x.png'],
    [256, 'icon_256x256.png'], [512, 'icon_256x256@2x.png'],
    [512, 'icon_512x512.png'], [1024, 'icon_512x512@2x.png'],
  ];
  for (const [size, name] of spec) {
    execFileSync('rsvg-convert', ['-w', String(size), '-h', String(size), markPath, '-o', path.join(iconset, name)]);
  }
  execFileSync('iconutil', ['-c', 'icns', iconset, '-o', outPath]);
}

/* ------------------------------------------------------------------ */
/* Target manifest                                                     */
/* ------------------------------------------------------------------ */

/**
 * Existing pixel dimensions are preserved verbatim, including the places
 * where they disagree with the filename (realfavicongenerator emitted
 * mstile-70x70 at 128px, mstile-150x150 at 270px, and so on). Renaming or
 * "correcting" those would churn every referencing manifest for no gain.
 */
const png = (to, size, variant = 'alpha') => ({ kind: 'png', to, size, variant });

const TARGETS = [
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: data-browser web app',
    dir: 'browser/data-browser/public/app_data/images',
    files: [
      png('favicon-16x16.png', 16),
      png('favicon-32x32.png', 32),
      png('icon.png', 152),
      png('apple-touch-icon.png', 180, 'flat'),
      png('android-chrome-192x192.png', 192),
      png('android-chrome-512x512.png', 512),
      png('maskable_icon_x128.png', 128, 'maskable'),
      png('maskable_icon_x192.png', 192, 'maskable'),
      png('maskable_icon_x384.png', 384, 'maskable'),
      png('maskable_icon_x512.png', 512, 'maskable'),
      png('maskable_icon.png', 1024, 'maskable'),
      png('mstile-70x70.png', 128),
      png('mstile-144x144.png', 144),
      png('mstile-150x150.png', 270),
      png('mstile-310x310.png', 558),
      png('mstile-310x150.png', [558, 270]),
      { kind: 'ico', to: 'favicon.ico' },
      // Safari flattens pinned-tab icons to one ink — needs the mono lockup.
      { kind: 'svg', to: 'mask-icon.svg', mark: 'atomicMono' },
    ],
  },
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: Tauri desktop + iOS',
    dir: 'desktop/icons',
    files: [
      png('32x32.png', 32),
      png('64x64.png', 64),
      png('128x128.png', 128),
      png('128x128@2x.png', 256),
      png('icon.png', 512),
      png('atomic-icon.png', 760),
      png('StoreLogo.png', 50),
      png('Square30x30Logo.png', 30),
      png('Square44x44Logo.png', 44),
      png('Square71x71Logo.png', 71),
      png('Square89x89Logo.png', 89),
      png('Square107x107Logo.png', 107),
      png('Square142x142Logo.png', 142),
      png('Square150x150Logo.png', 150),
      png('Square284x284Logo.png', 284),
      png('Square310x310Logo.png', 310),
      { kind: 'ico', to: 'icon.ico' },
      { kind: 'icns', to: 'icon.icns' },
    ],
  },
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: Tauri iOS app icons (opaque — App Store requires no alpha)',
    dir: 'desktop/icons/ios',
    files: [
      png('AppIcon-20x20@1x.png', 20, 'flat'),
      png('AppIcon-20x20@2x.png', 40, 'flat'),
      png('AppIcon-20x20@2x-1.png', 40, 'flat'),
      png('AppIcon-20x20@3x.png', 60, 'flat'),
      png('AppIcon-29x29@1x.png', 29, 'flat'),
      png('AppIcon-29x29@2x.png', 58, 'flat'),
      png('AppIcon-29x29@2x-1.png', 58, 'flat'),
      png('AppIcon-29x29@3x.png', 87, 'flat'),
      png('AppIcon-40x40@1x.png', 40, 'flat'),
      png('AppIcon-40x40@2x.png', 80, 'flat'),
      png('AppIcon-40x40@2x-1.png', 80, 'flat'),
      png('AppIcon-40x40@3x.png', 120, 'flat'),
      png('AppIcon-60x60@2x.png', 120, 'flat'),
      png('AppIcon-60x60@3x.png', 180, 'flat'),
      png('AppIcon-76x76@1x.png', 76, 'flat'),
      png('AppIcon-76x76@2x.png', 152, 'flat'),
      png('AppIcon-83.5x83.5@2x.png', 167, 'flat'),
      png('AppIcon-512@2x.png', 1024, 'flat'),
    ],
  },
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: mdBook docs',
    dir: 'docs/theme',
    files: [png('favicon.png', 76), { kind: 'svg', to: 'favicon.svg' }],
  },
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: svelte package',
    dir: 'browser/svelte/static',
    files: [png('favicon.png', 128)],
  },
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: sveltekit starter template',
    dir: 'browser/create-template/templates/sveltekit-site/static',
    files: [png('favicon.png', 128)],
  },
  {
    mark: 'atomic',
    root: SERVER_ROOT,
    label: 'atomic-server: repo-root square mark',
    dir: '.',
    files: [{ kind: 'svg', to: 'logo-square.svg' }],
  },

  /* Atomic Canvas — its own mark, same family. See brand/src/canvas-mark.svg. */
  {
    mark: 'canvas',
    root: SERVER_ROOT,
    label: 'atomic-canvas: web',
    dir: 'flutter/web',
    files: [png('favicon.png', 16)],
  },
  {
    mark: 'canvas',
    root: SERVER_ROOT,
    label: 'atomic-canvas: web PWA icons',
    dir: 'flutter/web/icons',
    files: [
      png('Icon-192.png', 192),
      png('Icon-512.png', 512),
      png('Icon-maskable-192.png', 192, 'maskable'),
      png('Icon-maskable-512.png', 512, 'maskable'),
    ],
  },
  {
    mark: 'canvas',
    root: SERVER_ROOT,
    label: 'atomic-canvas: iOS',
    dir: 'flutter/ios/Runner/Assets.xcassets/AppIcon.appiconset',
    files: [
      png('Icon-App-20x20@1x.png', 20, 'flat'),
      png('Icon-App-20x20@2x.png', 40, 'flat'),
      png('Icon-App-20x20@3x.png', 60, 'flat'),
      png('Icon-App-29x29@1x.png', 29, 'flat'),
      png('Icon-App-29x29@2x.png', 58, 'flat'),
      png('Icon-App-29x29@3x.png', 87, 'flat'),
      png('Icon-App-40x40@1x.png', 40, 'flat'),
      png('Icon-App-40x40@2x.png', 80, 'flat'),
      png('Icon-App-40x40@3x.png', 120, 'flat'),
      png('Icon-App-60x60@2x.png', 120, 'flat'),
      png('Icon-App-60x60@3x.png', 180, 'flat'),
      png('Icon-App-76x76@1x.png', 76, 'flat'),
      png('Icon-App-76x76@2x.png', 152, 'flat'),
      png('Icon-App-83.5x83.5@2x.png', 167, 'flat'),
      png('Icon-App-1024x1024@1x.png', 1024, 'flat'),
    ],
  },
  ...['mdpi:48', 'hdpi:72', 'xhdpi:96', 'xxhdpi:144', 'xxxhdpi:192'].map(d => {
    const [density, size] = d.split(':');
    return {
      mark: 'canvas',
      root: SERVER_ROOT,
      label: `atomic-canvas: Android ${density}`,
      dir: `flutter/android/app/src/main/res/mipmap-${density}`,
      files: [png('ic_launcher.png', Number(size))],
    };
  }),

  // Android uses these checked-in launcher resources, not desktop/icons.
  ...['mdpi:48:108', 'hdpi:72:162', 'xhdpi:96:216', 'xxhdpi:144:324', 'xxxhdpi:192:432'].map(d => {
    const [density, size, foreground] = d.split(':');
    return {
      mark: 'atomic', root: SERVER_ROOT,
      label: `atomic-server: Tauri Android ${density}`,
      dir: `desktop/gen/android/app/src/main/res/mipmap-${density}`,
      files: [
        png('ic_launcher.png', Number(size), 'flat'),
        png('ic_launcher_round.png', Number(size), 'flat'),
        png('ic_launcher_foreground.png', Number(foreground), 'maskable'),
      ],
    };
  }),

  /* Sibling repos — skipped when the checkout is not present. */
  {
    mark: 'atomic',
    root: SAAS_ROOT,
    label: 'atomic-saas: portal',
    dir: 'portal/public',
    files: [
      { kind: 'svg', to: 'favicon.svg' },
      png('favicon-32x32.png', 32),
      png('apple-touch-icon.png', 180, 'flat'),
      { kind: 'ico', to: 'favicon.ico' },
    ],
  },
  {
    mark: 'atomic',
    root: SAAS_ROOT,
    label: 'atomic-saas: marketing site',
    // Next.js App Router picks these up by filename convention — no <link> tags.
    dir: 'site/src/app',
    files: [
      { kind: 'svg', to: 'icon.svg' },
      png('apple-icon.png', 180, 'flat'),
    ],
  },

];

/* ------------------------------------------------------------------ */
/* Driver                                                              */
/* ------------------------------------------------------------------ */

// Xcode builds from its own checked-in asset catalog, not desktop/icons/ios.
const iosIcons = TARGETS.find(target => target.dir === 'desktop/icons/ios');
TARGETS.push({
  ...iosIcons,
  label: 'atomic-server: Tauri Xcode app icon catalog',
  dir: 'desktop/gen/apple/Assets.xcassets/AppIcon.appiconset',
});

const TMP = mkdtempSync(path.join(tmpdir(), 'atomic-brand-'));
let written = 0;
let skipped = 0;

function build(markPath, file, outPath) {
  switch (file.kind) {
    case 'png': return render(markPath, file.size, file.variant, outPath);
    case 'svg': return renderSvg(markPath, outPath);
    case 'ico': return renderIco(markPath, outPath);
    case 'icns': return renderIcns(markPath, outPath);
    default: throw new Error(`unknown target kind: ${file.kind}`);
  }
}

try {
  for (const target of TARGETS) {
    if (!existsSync(target.root)) {
      console.warn(`  skip  ${target.label} — no checkout at ${target.root}`);
      skipped += target.files.length;
      continue;
    }

    const outDir = path.join(target.root, target.dir);
    mkdirSync(outDir, { recursive: true });
    console.log(`\n${target.label}`);

    for (const file of target.files) {
      const markPath = MARKS[file.mark ?? target.mark];

      // .icns needs macOS iconutil; everything else is portable.
      if (file.kind === 'icns' && process.platform !== 'darwin') {
        console.warn(`  skip  ${file.to} — .icns needs macOS iconutil`);
        skipped++;
        continue;
      }

      build(markPath, file, path.join(outDir, file.to));
      written++;
      console.log(`  ok    ${file.to}`);
    }
  }

  console.log(`\nWrote ${written} file(s)${skipped ? `, skipped ${skipped}` : ''}.`);
  console.log('Review with `git diff`; an empty diff means nothing drifted.');
} finally {
  rmSync(TMP, { recursive: true, force: true });
}

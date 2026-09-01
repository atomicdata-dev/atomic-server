import {
  useEffect,
  useId,
  useState,
  type AnimationEvent,
  type FormEvent,
  type JSX,
} from 'react';
import {
  CAPTCHA_VALUE_KEY,
  type FormDefinition,
  type FormErrors,
  type FormValues,
} from './types.js';
import {
  PAGE_ANIMATION_PREFIX,
  pageTransitionsEnabled,
  phaseDeadlineMs,
  staggerSlots,
  staggerSpanStyle,
  staggerStyle,
  transitionClass,
  useReducedMotion,
  type PageTransition,
  type TransitionDirection,
} from './pageTransition.js';
import { validatePage, validateAll } from './validation.js';
import { computeVisibility } from './conditions.js';
import { useFormDraft } from './draft.js';
import { FieldInput } from './FieldInput.js';
import { FormMarkdown } from './FormMarkdown.js';
import { InfoBox } from './InfoBox.js';

export type SubmitResult =
  | { ok: true }
  | { ok: false; message?: string; errors?: FormErrors };

export interface FormRendererProps {
  definition: FormDefinition;
  onSubmit: (values: FormValues) => Promise<SubmitResult>;
  /** Disables the honeypot field and turns Submit into a no-op — used by the
   * data-browser builder's preview mode, which renders the same definition
   * JSON but must never write a real submission. */
  preview?: boolean;
  /** Enables partial-submission drafts, stored under this key in the
   * visitor's `localStorage` (see `draft.ts`). Host-supplied so the
   * data-browser's preview — which renders the same definition — can leave it
   * off and never touch a real visitor's storage. `form-app` derives it from
   * the definition's publish slug (stable whether the visitor arrived via the
   * slug or the DID) plus any invite code. A form whose owner turned drafts
   * off (`styling.saveDrafts === false`) ignores the key. */
  draftKey?: string;
  className?: string;
}

type Status = 'filling' | 'submitting' | 'submitted' | 'error';

export function FormRenderer({
  definition,
  onSubmit,
  preview = false,
  draftKey,
  className,
}: FormRendererProps): JSX.Element {
  const draft = useFormDraft(
    definition,
    !preview && definition.styling.saveDrafts !== false ? draftKey : undefined,
  );
  const [pageIndex, setPageIndex] = useState(draft.restored?.pageIndex ?? 0);
  const [values, setValues] = useState<FormValues>(
    () => draft.restored?.values ?? {},
  );
  // A restored draft seeds the form immediately, but the visitor is asked
  // before carrying on with it: the answers behind the dialog are the context
  // for the question, and Reset is right there for whoever did not expect to
  // find them.
  const [askResume, setAskResume] = useState(draft.restored !== undefined);
  const [resumeDialog, setResumeDialog] = useState<HTMLDialogElement | null>(
    null,
  );
  const [errors, setErrors] = useState<FormErrors>({});
  const [status, setStatus] = useState<Status>('filling');
  const [serverMessage, setServerMessage] = useState<string | undefined>();
  const [honeypot, setHoneypot] = useState('');
  const [transition, setTransition] = useState<PageTransition | null>(null);
  const groupId = useId();
  const reducedMotion = useReducedMotion();
  const animate = pageTransitionsEnabled(definition.styling, reducedMotion);

  // ALTCHA proof-of-work captcha (server-provided config; previews get no
  // config and render no widget). The <altcha-widget> element itself is
  // registered by the host app (form-app's `import 'altcha'`).
  const captcha =
    !preview && definition.captcha?.provider === 'altcha'
      ? definition.captcha
      : undefined;
  const [captchaVerified, setCaptchaVerified] = useState(false);
  const [captchaEl, setCaptchaEl] = useState<HTMLElement | null>(null);

  useEffect(() => {
    if (!captchaEl) return;

    const onStateChange = (event: Event) => {
      const state = (event as CustomEvent<{ state?: string }>).detail?.state;
      setCaptchaVerified(state === 'verified');
    };

    captchaEl.addEventListener('statechange', onStateChange);

    return () => captchaEl.removeEventListener('statechange', onStateChange);
  }, [captchaEl]);

  const page = definition.pages[pageIndex];
  const visibility = computeVisibility(definition, values);
  const visiblePageIndices = visibility.pageIndices;
  const visiblePos = visiblePageIndices.indexOf(pageIndex);
  const isLastPage =
    visiblePageIndices.length === 0 ||
    visiblePos === visiblePageIndices.length - 1 ||
    (visiblePos < 0 && pageIndex >= (visiblePageIndices.at(-1) ?? 0));
  const progress =
    visiblePageIndices.length > 1 &&
    definition.styling.showProgressBar !== false
      ? Math.round(
          ((Math.max(visiblePos, 0) + 1) / visiblePageIndices.length) * 100,
        )
      : undefined;

  const visiblePagesKey = visiblePageIndices.join(',');

  // If the current page was hidden by a later answer change (unusual —
  // page conditions typically reference earlier pages), snap to the
  // nearest still-visible page so the visitor isn't stuck on a blank one.
  useEffect(() => {
    const indices = visiblePagesKey
      ? visiblePagesKey.split(',').map(Number)
      : [];

    if (indices.length === 0) return;

    if (indices.includes(pageIndex)) return;

    const next = indices.find(i => i > pageIndex);
    setPageIndex(next ?? indices[indices.length - 1]);
  }, [pageIndex, visiblePagesKey]);

  // The blocks actually on screen, in order, each carrying the stagger slot
  // it starts at. A block claims more than one slot when it lays options out
  // on the page (see `staggerSlots`), so the running total — not the block
  // count — is what the fade-in's length is measured in.
  let slots = 0;
  const visibleBlocks = (page?.blocks ?? []).flatMap((block, index) => {
    if (!visibility.blocks[pageIndex]?.has(index)) return [];

    const entry = { block, index, slot: slots };
    slots += staggerSlots(block);

    return [entry];
  });

  /** Ends the current phase: the exit hands over to the arriving page, the
   * enter settles back to rest. Called by the phase's own `animationend`,
   * and by the deadline below if that never arrives. */
  const endPhase = () => {
    if (!transition) return;

    if (transition.phase === 'exit') {
      setPageIndex(transition.target);
      setTransition({ ...transition, phase: 'enter' });
    } else {
      setTransition(null);
    }
  };

  // The enter phase's clock, and the exit phase's safety net. The exit
  // normally ends on its own `animationend`; this catches the case where that
  // never comes (a form animating in a hidden tab, a class change coalesced
  // away under a stalled main thread) and would otherwise leave the visitor
  // parked on the page they were trying to leave. Cleared on unmount and
  // whenever a phase ends on its own.
  useEffect(() => {
    if (!transition) return;

    const timer = setTimeout(endPhase, phaseDeadlineMs(transition, slots));

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [transition]);

  const handleAnimationEnd = (event: AnimationEvent<HTMLDivElement>) => {
    // Only the page's own exit animation ends a phase. The staggered fades of
    // the arriving page bubble their `animationend` up through this same
    // handler, and the first of them to land would otherwise strip the enter
    // class off — cutting every later element's fade before it started.
    if (event.target !== event.currentTarget) return;

    if (!event.animationName.startsWith(PAGE_ANIMATION_PREFIX)) return;

    endPhase();
  };

  // Persist on every answer/page change. `save` debounces internally and
  // flushes on `pagehide`, so this fires far more often than it writes.
  useEffect(() => {
    draft.save(values, pageIndex);
  }, [draft, values, pageIndex]);

  // `showModal()` — not the `open` attribute — is what puts the dialog in the
  // top layer with a backdrop, a focus trap and Escape handling, none of
  // which React can express declaratively.
  useEffect(() => {
    if (!resumeDialog || resumeDialog.open) return;

    resumeDialog.showModal();
  }, [resumeDialog]);

  /** Keeps the restored answers. The form is already seeded with them, so
   * this only has to dismiss the question. */
  const resumeDraft = () => setAskResume(false);

  /** Throws the restored answers away and starts the form from scratch. The
   * save effect above then sees an empty value set and removes the stored
   * draft rather than rewriting it. */
  const resetDraft = () => {
    draft.clear();
    setValues({});
    setErrors({});
    setPageIndex(0);
    setTransition(null);
    setAskResume(false);
  };

  const setValue = (mapsTo: string, value: unknown) => {
    setValues(prev => ({ ...prev, [mapsTo]: value }));
    setErrors(prev => {
      if (!(mapsTo in prev)) return prev;

      const next = { ...prev };
      delete next[mapsTo];

      return next;
    });
  };

  /** Swaps the rendered page, playing the exit/enter animation around the
   * swap when enabled. The leaving page stays mounted for the exit phase, so
   * the content only changes once it is off the screen. */
  const goToPage = (target: number, direction: TransitionDirection) => {
    if (target === pageIndex) return;

    if (!animate) {
      setPageIndex(target);

      return;
    }

    setTransition({ phase: 'exit', direction, target });
  };

  /** The neighbour of the current page among the visible ones. */
  const siblingPage = (step: 1 | -1) => {
    const pos = visiblePageIndices.indexOf(pageIndex);
    const targetPos =
      step === 1 ? (pos < 0 ? 0 : pos + 1) : Math.max(pos - 1, 0);

    return visiblePageIndices[targetPos] ?? pageIndex;
  };

  const goNext = () => {
    // A second click during the exit phase would queue another page change
    // against a stale index — the buttons stay inert until the swap lands.
    if (transition?.phase === 'exit') return;

    const result = validatePage(definition, pageIndex, values);

    if (Object.keys(result.errors).length > 0) {
      setErrors(prev => ({ ...prev, ...result.errors }));

      return;
    }

    goToPage(siblingPage(1), 'forward');
  };

  const goBack = () => {
    if (transition?.phase === 'exit') return;

    goToPage(siblingPage(-1), 'back');
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (preview) return;

    const result = validateAll(definition, values);

    if (Object.keys(result.errors).length > 0) {
      setErrors(result.errors);

      // Jump to the first *visible* page that has an error so the visitor sees it.
      const firstErrorPage = visibility.pageIndices.find(i =>
        definition.pages[i].blocks.some(
          (b, bi) =>
            b.kind === 'field' &&
            visibility.blocks[i]?.has(bi) &&
            b.mapsTo in result.errors,
        ),
      );

      if (firstErrorPage !== undefined) setPageIndex(firstErrorPage);

      return;
    }

    setStatus('submitting');
    // The widget stores its solved payload in a hidden input named 'altcha'
    // inside this <form>. Read it before the await — the event's
    // currentTarget is only valid synchronously.
    const captchaPayload = captcha
      ? ((new FormData(e.currentTarget as HTMLFormElement).get('altcha') as
          | string
          | null) ?? '')
      : undefined;
    // The honeypot's (and captcha's) value rides along under its own field
    // key so the host app (form-app) can lift it out to the submit body's
    // top-level `hp` / `altcha` fields without FormRenderer needing to know
    // the wire format.
    const outcome = await onSubmit({
      ...result.values,
      [definition.honeypotField]: honeypot,
      ...(captchaPayload === undefined
        ? {}
        : { [CAPTCHA_VALUE_KEY]: captchaPayload }),
    });

    if (outcome.ok) {
      // The answers are on the server now; leaving them on the device would
      // re-fill the form for the next visitor sharing this browser.
      draft.clear();
      setStatus('submitted');
    } else {
      setStatus('error');
      setServerMessage(outcome.message);

      if (outcome.errors) setErrors(outcome.errors);
    }
  };

  if (status === 'submitted') {
    const message =
      (definition.settings.confirmationMessage as string | undefined) ??
      'Thank you, your response has been recorded.';

    return (
      <div className={className}>
        <div className='atomic-form-success' role='status'>
          {message}
        </div>
      </div>
    );
  }

  return (
    <form className={className} onSubmit={handleSubmit} noValidate>
      {progress !== undefined && (
        <div className='atomic-form-progress' aria-hidden='true'>
          <div
            className='atomic-form-progress-bar'
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {askResume && (
        // Rendered inside the <form> so the theme's custom properties reach
        // it: the top layer changes painting order, not CSS inheritance.
        // Both buttons are explicitly type='button' — a bare <button> here
        // would submit the form.
        <dialog
          ref={setResumeDialog}
          className='atomic-form-draft-dialog'
          aria-labelledby={`${groupId}-resume-title`}
          // Escape (and any other cancel) keeps the answers: dismissing a
          // question must never be the destructive choice.
          onCancel={resumeDraft}
        >
          <h2
            className='atomic-form-draft-title'
            id={`${groupId}-resume-title`}
          >
            Continue where you left off?
          </h2>
          <p className='atomic-form-draft-text'>
            You started filling in this form on this device, and your answers
            are still here.
          </p>
          <div className='atomic-form-draft-actions'>
            <button
              type='button'
              className='atomic-form-button atomic-form-button-secondary'
              onClick={resetDraft}
            >
              Reset
            </button>
            <button
              type='button'
              className='atomic-form-button'
              onClick={resumeDraft}
              autoFocus
            >
              Continue
            </button>
          </div>
        </dialog>
      )}

      <div
        className={`atomic-form-blocks ${transitionClass(transition)}`.trim()}
        style={staggerSpanStyle(slots)}
        onAnimationEnd={handleAnimationEnd}
      >
        {visibleBlocks.map(({ block, index, slot }) => {
          // One wrapper per block, rather than the stagger class on each of
          // the four block elements: it is the only thing every kind has in
          // common, and `FormMarkdown` / `InfoBox` would otherwise both need
          // to forward a style through.
          const stagger = {
            className: 'atomic-form-stagger',
            style: staggerStyle(slot),
          };

          if (block.kind === 'heading') {
            return (
              <div key={index} {...stagger}>
                <h3 className='atomic-form-heading'>{block.text}</h3>
              </div>
            );
          }

          if (block.kind === 'paragraph') {
            return (
              <div key={index} {...stagger}>
                <FormMarkdown
                  className='atomic-form-paragraph'
                  text={block.text}
                />
              </div>
            );
          }

          if (block.kind === 'info-box') {
            return (
              <div key={index} {...stagger}>
                <InfoBox block={block} />
              </div>
            );
          }

          const inputId = `${groupId}-${block.mapsTo}`;
          // A distinct id from the input's own — `htmlFor` on text-type
          // fields points AT the input, while `aria-labelledby` on
          // radio/multi-select groups (which have no single input to
          // `htmlFor`) points at this label instead. Giving the label the
          // same id as the input it labels would be a duplicate-id
          // collision, breaking the browser's for/id association.
          const labelId = `${inputId}-label`;
          const error = errors[block.mapsTo];
          const showLabel = block.type !== 'checkbox';

          // A field whose options are laid out on the page fades in parts,
          // not as a block: its label and helper text take the field's own
          // slot, and each option the slots after it. Fading the field as a
          // whole *as well* would fade those options a second time, as a
          // group — and a group fading in together is exactly what the
          // ripple is meant to replace.
          const asParts = staggerSlots(block) > 1;
          const heading = asParts ? stagger : undefined;

          return (
            <div
              key={block.mapsTo}
              className={`atomic-form-field${asParts ? '' : ` ${stagger.className}`}`}
              style={asParts ? undefined : stagger.style}
            >
              {showLabel && (
                <label
                  className={`atomic-form-label${heading ? ` ${heading.className}` : ''}`}
                  style={heading?.style}
                  htmlFor={inputId}
                  id={labelId}
                >
                  {block.label}
                  {block.required && (
                    <span className='atomic-form-required'>*</span>
                  )}
                </label>
              )}
              {block.description && (
                <FormMarkdown
                  className={`atomic-form-description${heading ? ` ${heading.className}` : ''}`}
                  style={heading?.style}
                  text={block.description}
                />
              )}
              <FieldInput
                field={block}
                value={values[block.mapsTo]}
                onChange={v => setValue(block.mapsTo, v)}
                inputId={inputId}
                labelId={labelId}
                staggerBase={slot}
              />
              {error && (
                <p className='atomic-form-error' role='alert'>
                  {error}
                </p>
              )}
            </div>
          );
        })}
      </div>

      {captcha && (
        // Mounted on every page (hidden until the last) so the background
        // solve starts at load, not when the visitor reaches Submit.
        <div
          className='atomic-form-captcha'
          style={isLastPage ? undefined : { display: 'none' }}
        >
          <altcha-widget
            ref={setCaptchaEl}
            challenge={captcha.challengeUrl}
            auto='onload'
          />
        </div>
      )}

      {!preview && (
        <input
          type='text'
          name={definition.honeypotField}
          value={honeypot}
          onChange={e => setHoneypot(e.target.value)}
          tabIndex={-1}
          autoComplete='off'
          aria-hidden='true'
          className='atomic-form-honeypot'
        />
      )}

      {status === 'error' && (
        <p className='atomic-form-error atomic-form-submit-error' role='alert'>
          {serverMessage ??
            'Something went wrong submitting this form. Please try again.'}
        </p>
      )}

      <div className='atomic-form-nav'>
        {pageIndex > 0 && visiblePos > 0 && (
          <button
            type='button'
            className='atomic-form-button atomic-form-button-secondary'
            onClick={goBack}
          >
            Back
          </button>
        )}
        {!isLastPage && (
          <button type='button' className='atomic-form-button' onClick={goNext}>
            Next
          </button>
        )}
        {isLastPage && (
          <button
            type='submit'
            className='atomic-form-button'
            disabled={
              status === 'submitting' || (!!captcha && !captchaVerified)
            }
          >
            {status === 'submitting' ? 'Submitting…' : 'Submit'}
          </button>
        )}
      </div>
    </form>
  );
}

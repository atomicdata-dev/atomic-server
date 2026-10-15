// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import DrivePage from './DrivePage';

const state = vi.hoisted(() => ({
  drop: undefined as ((files: File[]) => Promise<void>) | undefined,
  store: {
    getResourceAncestry: vi.fn(),
    uploadFiles: vi.fn(),
  },
}));

vi.mock('@tomic/react', () => ({
  Datatype: { MARKDOWN: 'markdown' },
  core: { properties: { description: 'description' } },
  useCanWrite: () => false,
  useStore: () => state.store,
}));

vi.mock('react-dropzone', () => ({
  useDropzone: ({ onDrop }: { onDrop: (files: File[]) => Promise<void> }) => {
    state.drop = onDrop;

    return { getRootProps: () => ({}), isDragActive: false };
  },
}));

vi.mock('@components/Containers', () => ({
  ContainerNarrow: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
}));
vi.mock('@components/Button', () => ({
  Button: ({ children }: { children: React.ReactNode }) => (
    <button>{children}</button>
  ),
}));
vi.mock('@helpers/AppSettings', () => ({
  useSettings: () => ({ drive: 'did:ad:settings-drive', setDrive: vi.fn() }),
}));
vi.mock('@components/SideBar/DriveSwitcher', () => ({
  DriveSwitcher: () => <button>Switch Drive</button>,
  DriveSwitcherChevronTrigger: () => <button />,
}));
vi.mock('@components/EditableTitle', () => ({
  EditableTitle: () => <h1>Drive title</h1>,
}));
vi.mock('@hooks/useVisibleDriveChildren', () => ({
  useVisibleDriveChildren: () => ({
    subjects: [],
    allSubjects: [],
    loading: false,
    total: 0,
  }),
}));
vi.mock('@hooks/useIsPrivateDrive', () => ({ useIsPrivateDrive: () => false }));
vi.mock('@components/Drives/PrivateDriveBadge', () => ({
  PrivateDriveBadge: () => <span />,
}));
vi.mock('@components/ResourceDecorations', () => ({
  ResourceCoverImage: () => <div />,
}));
vi.mock('@components/Row', () => ({
  Column: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  Row: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock('react-icons/fa6', () => ({
  FaGear: () => <svg />,
}));
vi.mock('@components/Dialog/useDialog', () => ({
  useDialog: () => [{}, vi.fn(), vi.fn(), false],
}));
vi.mock('./DriveSettingsDialog', () => ({
  DriveSettingsDialog: () => <div />,
}));
vi.mock('./DriveHome', () => ({
  ActivityFeed: () => <div />,
  DrivePeople: () => <div />,
  QuickCreateCards: () => <div />,
  RecentlyOpened: () => <div />,
  ResourceTiles: () => <div />,
  SectionTitle: ({ children }: { children: React.ReactNode }) => (
    <h2>{children}</h2>
  ),
}));
vi.mock('@hooks/useVectorIndexStatus', () => ({
  useVectorIndexStatus: () => false,
}));
vi.mock('@components/VectorIndexingIndicator', () => ({
  VectorIndexingIndicator: () => <span />,
}));
vi.mock('@components/forms/ValueForm/ValueFormAddButton', () => ({
  ValueFormAddButton: () => <button />,
}));

const theme = {
  darkMode: false,
  colors: { textLight: '#888' },
  radius: '4px',
  margin: 1,
} as unknown as DefaultTheme;

describe('drive root file drops', () => {
  it.each([1, 2])(
    'uploads %i dropped file(s) beneath the displayed drive, not the settings drive',
    async fileCount => {
      state.drop = undefined;
      state.store.uploadFiles.mockClear();
      state.store.uploadFiles.mockResolvedValue([]);
      const resource = { subject: 'did:ad:viewed-drive' };
      const files = Array.from(
        { length: fileCount },
        (_, index) =>
          new File([`file ${index}`], `file-${index}.txt`, {
            type: 'text/plain',
          }),
      );

      renderToStaticMarkup(
        <ThemeProvider theme={theme}>
          <DrivePage resource={resource as never} />
        </ThemeProvider>,
      );

      expect(state.drop).toBeTypeOf('function');
      await state.drop!(files);

      expect(state.store.uploadFiles).toHaveBeenCalledWith(
        files,
        resource.subject,
      );
    },
  );
});

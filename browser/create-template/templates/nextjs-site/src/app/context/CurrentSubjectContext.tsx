import { env } from '@/env';
import { createContext, useContext, useState } from 'react';

interface CurrentSubjectContextType {
  currentSubject: string;
  setCurrentSubject: (newSubject: string) => void;
}

const CurrentSubjectContext = createContext<
  CurrentSubjectContextType | undefined
>(undefined);

export const CurrentSubjectProvider = ({
  children,
}: {
  children: Readonly<React.ReactNode>;
}) => {
  const [currentSubject, setCurrentSubject] = useState<string>(
    env.NEXT_PUBLIC_WEBSITE_RESOURCE,
  );
  return (
    <CurrentSubjectContext.Provider
      value={{
        currentSubject,
        setCurrentSubject,
      }}
    >
      {children}
    </CurrentSubjectContext.Provider>
  );
};

export const useCurrentSubject = () => {
  const context = useContext(CurrentSubjectContext);
  if (!context) {
    throw new Error('useSubject must be used within a SubjectProvider');
  }
  return context;
};

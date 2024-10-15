import { createContext, useContext } from 'react';

interface ResourceFormContext {
  inResourceForm: boolean;
}

export const ResourceFormContext = createContext<ResourceFormContext>({
  inResourceForm: false,
});

export const RESOURCE_FORM_CONTEXT_VALUE = {
  inResourceForm: true,
} as ResourceFormContext;

export function useResourceFormContext() {
  return useContext(ResourceFormContext);
}

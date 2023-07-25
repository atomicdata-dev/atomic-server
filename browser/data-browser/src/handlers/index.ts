import { Store, StoreEvents } from '@tomic/react';
import { saveAgentToLocalStorage } from '../helpers/agentStorage';
import { errorHandler } from './errorHandler';
import {
  buildSideBarNewResourceHandler,
  buildSideBarRemoveResourceHandler,
} from './sideBarHandler';

export function registerHandlers(store: Store) {
  store.on(
    StoreEvents.ResourceManuallyCreated,
    buildSideBarNewResourceHandler(store),
  );
  store.on(
    StoreEvents.ResourceRemoved,
    buildSideBarRemoveResourceHandler(store),
  );
  store.on(StoreEvents.Error, errorHandler);
  store.on(StoreEvents.AgentChanged, saveAgentToLocalStorage);
}

import { registerBasicInstanceHandlers } from './BasicInstanceHandlers';
import { registerCustomForms } from './CustomForms';

export const registerCustomCreateActions = () => {
  registerCustomForms();
  registerBasicInstanceHandlers();
};

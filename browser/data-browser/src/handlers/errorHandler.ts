import toast from 'react-hot-toast';
import { handleErrorBugsnag } from '../helpers/loggingHandlers';

/// Logs the error to Bugsnag, throws a toast message
export const errorHandler = (e: Error) => {
  console.error(e);
  handleErrorBugsnag(e);

  const message = e.message;

  toast.error(message);
};

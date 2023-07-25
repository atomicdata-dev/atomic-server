import toast from 'react-hot-toast';
import { handleError } from '../helpers/loggingHandlers';

export const errorHandler = (e: Error) => {
  handleError(e);

  const message = e.message;

  toast.error(message);
};

import { useEffect, useState } from 'react';
import { useMediaQuery } from './useMediaQuery';

const DEFAULT_FILE_SIZE_LIMIT = 10 * 1024 * 1024; // 10 MB
const REDUCED_FILE_SIZE_LIMIT = 1024 * 100; // 100 KB

export function useFilePreviewSizeLimit() {
  const [limit, setLimit] = useState(DEFAULT_FILE_SIZE_LIMIT);

  const prefersReducedData = useMediaQuery('(prefers-reduced-data: reduce)');

  useEffect(() => {
    if (prefersReducedData) {
      setLimit(REDUCED_FILE_SIZE_LIMIT);
    } else {
      setLimit(DEFAULT_FILE_SIZE_LIMIT);
    }
  }, [prefersReducedData]);

  return limit;
}

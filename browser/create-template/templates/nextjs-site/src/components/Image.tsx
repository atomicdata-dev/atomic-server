'use client';

import { Image as AtomicImage } from '@tomic/react';

export const Image = ({ subject, alt }: { subject: string; alt: string }) => {
  return <AtomicImage subject={subject} alt={alt} />;
};

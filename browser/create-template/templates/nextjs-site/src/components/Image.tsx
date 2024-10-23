'use client';

import { Image as AtomicImage } from '@tomic/react';
import NoSSR from './NoSSR';
import React from 'react';

export const Image = ({ subject, alt }: { subject: string; alt: string }) => {
  return (
    <NoSSR>
      <AtomicImage subject={subject} alt={alt} />
    </NoSSR>
  );
};

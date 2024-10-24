'use client';

import Container from '@/components/Layout/Container';
import Link from 'next/link';

export default function Error({
  error,
}: {
  error: Error & { digest?: string };
}) {
  return (
    <Container>
      <h1>{error.name}</h1>
      <p>
        Go to <Link href='/'>home</Link>
      </p>
    </Container>
  );
}

'use client';

import Container from '@/components/Layout/Container';

export default function Error({
  error,
}: {
  error: Error & { digest?: string };
}) {
  return (
    <Container>
      <h1>{error.name}</h1>
      <p>
        Go to <a href='/'>home</a>
      </p>
    </Container>
  );
}

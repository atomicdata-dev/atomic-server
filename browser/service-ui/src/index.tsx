import type { HTMLAttributes } from 'react';

export const CLOUD_VAULT = 'Cloud Vault';
export const CLOUD_SERVER = 'Cloud Server';
export const CLOUD_VAULT_DESCRIPTION =
  'Keep an encrypted copy of this workspace in AtomicServer.eu. It is sealed on this device, so we store it without being able to read it.';
export const CLOUD_SERVER_DESCRIPTION =
  'A hosted workspace on AtomicServer.eu: shareable links, search across everything, API access, and no waiting on another device to be awake. Unlike Cloud Vault, our servers process what you put here.';
export const CLOUD_SERVER_PLAN_DESCRIPTION =
  'Server plans apply to one drive. If this drive needs a plan, checkout shows the price before you pay. Connecting your account is free.';
export const CLOUD_SERVER_SETUP = 'Set up Cloud Server';
export const CLOUD_VAULT_ON = 'Cloud Vault is on';

export function ServiceSection({
  className = '',
  ...props
}: HTMLAttributes<HTMLElement>) {
  return (
    <section {...props} className={`atomic-service-section ${className}`} />
  );
}
export function ServiceBody({
  className = '',
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={`atomic-service-body ${className}`} />;
}
export function ServiceTitle({
  className = '',
  children,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3 {...props} className={`atomic-service-title ${className}`}>
      {children}
    </h3>
  );
}
export function ServiceDescription({
  className = '',
  ...props
}: HTMLAttributes<HTMLParagraphElement>) {
  return <p {...props} className={`atomic-service-description ${className}`} />;
}
export function ServiceIcon({
  kind,
  active = false,
}: {
  kind: 'vault' | 'server';
  active?: boolean;
}) {
  return (
    <span
      className='atomic-service-icon'
      data-active={active}
      aria-hidden='true'
    >
      <svg viewBox='0 0 24 24' width='20' height='20' fill='currentColor'>
        {kind === 'vault' ? (
          <path d='M7 10V7a5 5 0 0 1 10 0v3h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2zm2 0h6V7a3 3 0 0 0-6 0z' />
        ) : (
          <path d='M7 19a5 5 0 0 1-1-9.9 6 6 0 0 1 11.7-1.6A5.8 5.8 0 0 1 18 19z' />
        )}
      </svg>
    </span>
  );
}

export function ServiceGroup({
  className = '',
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={`atomic-service-group ${className}`} />;
}

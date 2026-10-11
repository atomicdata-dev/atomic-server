/**
 * What Cloud Server hosting means for the owner's data. One text, shown
 * wherever hosting is offered, because it is what the owner agrees to.
 */
export function HostingConsentNotice() {
  return (
    <>
      <strong>Before you turn it on:</strong> unlike Cloud Vault, Cloud Server
      stores a readable, unencrypted copy of this workspace on our servers, so
      we can run search, shareable links and the API for it. Your sharing
      permissions still control who else sees it, and you can turn it off at any
      time.
    </>
  );
}

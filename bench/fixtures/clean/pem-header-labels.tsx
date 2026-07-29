// FP guard: PEM headers used as UI labels and input placeholders. A header
// with no base64 body after it carries no key material.

const certificateBeginsWith = '-----BEGIN CERTIFICATE-----';
const privateKeyBeginsWith = '-----BEGIN RSA PRIVATE KEY-----';

export function TLSFields() {
  return (
    <>
      <textarea placeholder="-----BEGIN PRIVATE KEY-----" rows={7} />
      <span>{privateKeyBeginsWith}</span>
      <span>{certificateBeginsWith}</span>
    </>
  );
}

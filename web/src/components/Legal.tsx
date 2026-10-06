// Copyright and licence line. Shown wherever the AGPL link used to stand
// alone: the sidebar footer, the auth pages and, on phones, the user menu.
export function Legal({ center = false }: { center?: boolean }) {
  const year = new Date().getFullYear();
  return (
    <p className={`legal${center ? " center" : ""}`}>
      <span>
        &copy; {year}{" "}
        <a href="https://coffeylabs.org" target="_blank" rel="noreferrer">
          Coffey Labs LLC
        </a>
      </span>
      <span className="legal-sep" aria-hidden="true">
        ·
      </span>
      <a href="https://git.coffeylabs.org/coffey-labs/ihasvpn" target="_blank" rel="noreferrer">
        AGPL-3.0 source
      </a>
    </p>
  );
}

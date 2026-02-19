import React from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';

const cards = [
  {
    title: 'Whitepaper',
    body: 'Learn PQE, ZK proofs, and BlueARC architecture in an Alice/Bob narrative format.',
    to: '/docs/whitepaper/pqe-alice-bob',
    cta: 'Read Whitepaper'
  },
  {
    title: 'Admin Handover',
    body: 'Operate pool, relayer, and treasury safely with admin controls and incident runbooks.',
    to: '/docs/admin/admin-handover',
    cta: 'Open Admin Docs'
  },
  {
    title: 'Legacy Docs',
    body: 'Reference implementation details, API contracts, release guides, and migration notes.',
    to: '/docs/legacy/relayer-api',
    cta: 'Browse Legacy'
  }
];

export default function Home() {
  const tigerLogo = useBaseUrl('/img/bluearc-tiger-logo.png');

  return (
    <main className="tiger-home">
      <section className="tiger-hero">
        <div className="tiger-hero__copy">
          <p className="tiger-chip">BLUEARC // 8BIT</p>
          <h1>Tiger Docs</h1>
          <p>
            BlueARC Privacy Protocol documentation hub for whitepaper narratives, operator playbooks, and verified
            security evidence.
          </p>
          <div className="tiger-actions">
            <Link className="button button--primary button--lg" to="/docs/intro">
              Start Reading
            </Link>
            <Link className="button button--secondary button--lg" to="/docs/whitepaper/whitepaper-system">
              System Overview
            </Link>
          </div>
        </div>
        <img className="tiger-hero__art" src={tigerLogo} alt="BlueARC Electric Tiger" />
      </section>

      <section className="tiger-grid">
        {cards.map((card) => (
          <article className="tiger-card" key={card.title}>
            <h2>{card.title}</h2>
            <p>{card.body}</p>
            <Link to={card.to}>{card.cta}</Link>
          </article>
        ))}
      </section>

      <section className="tiger-band">
        <div>
          <h3>Published test evidence</h3>
          <p>33 passing tests including security, replay, reentrancy, and invariant-style checks.</p>
        </div>
        <Link className="button button--outline button--primary" to="/docs/whitepaper/unit-tests">
          View Unit Tests
        </Link>
      </section>

      <section className="tiger-band">
        <div>
          <h3>Security and release records</h3>
          <p>Audit checklist mapping, smart contract security validation, and Sepolia release report.</p>
        </div>
        <Link className="button button--outline button--primary" to="/docs/whitepaper/security-audit">
          View Security Docs
        </Link>
      </section>
    </main>
  );
}

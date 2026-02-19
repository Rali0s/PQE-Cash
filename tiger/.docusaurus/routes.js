import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/doc/docs',
    component: ComponentCreator('/doc/docs', '910'),
    routes: [
      {
        path: '/doc/docs',
        component: ComponentCreator('/doc/docs', '4bf'),
        routes: [
          {
            path: '/doc/docs',
            component: ComponentCreator('/doc/docs', '0e7'),
            routes: [
              {
                path: '/doc/docs/admin/admin-controls',
                component: ComponentCreator('/doc/docs/admin/admin-controls', 'e8c'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/admin/admin-handover',
                component: ComponentCreator('/doc/docs/admin/admin-handover', 'b6b'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/admin/release-and-incident-runbook',
                component: ComponentCreator('/doc/docs/admin/release-and-incident-runbook', 'f25'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/intro',
                component: ComponentCreator('/doc/docs/intro', '94f'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/admin-ops',
                component: ComponentCreator('/doc/docs/legacy/admin-ops', '4e4'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/audit-checklist-coverage',
                component: ComponentCreator('/doc/docs/legacy/audit-checklist-coverage', '750'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/branding',
                component: ComponentCreator('/doc/docs/legacy/branding', '876'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/circuit-signal-schema',
                component: ComponentCreator('/doc/docs/legacy/circuit-signal-schema', '4ac'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/contract-interfaces-storage',
                component: ComponentCreator('/doc/docs/legacy/contract-interfaces-storage', 'db5'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/docker-runbook',
                component: ComponentCreator('/doc/docs/legacy/docker-runbook', 'd67'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/poseidon-p0-p3-checklist',
                component: ComponentCreator('/doc/docs/legacy/poseidon-p0-p3-checklist', 'd21'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/product-spec',
                component: ComponentCreator('/doc/docs/legacy/product-spec', '4c1'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/real-proof-generation-plan',
                component: ComponentCreator('/doc/docs/legacy/real-proof-generation-plan', '424'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/relayer-api',
                component: ComponentCreator('/doc/docs/legacy/relayer-api', 'aad'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/relayer-hosting-scaling-fees',
                component: ComponentCreator('/doc/docs/legacy/relayer-hosting-scaling-fees', '307'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/sepolia-release-report',
                component: ComponentCreator('/doc/docs/legacy/sepolia-release-report', '2ae'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/sepolia-release-runbook',
                component: ComponentCreator('/doc/docs/legacy/sepolia-release-runbook', '33e'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/smart-contract-security-report',
                component: ComponentCreator('/doc/docs/legacy/smart-contract-security-report', 'f8c'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/threat-model',
                component: ComponentCreator('/doc/docs/legacy/threat-model', 'dd5'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/legacy/ui-theme',
                component: ComponentCreator('/doc/docs/legacy/ui-theme', '63b'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/design-choice-relayer-poseidon-v2',
                component: ComponentCreator('/doc/docs/whitepaper/design-choice-relayer-poseidon-v2', '730'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/pqe-alice-bob',
                component: ComponentCreator('/doc/docs/whitepaper/pqe-alice-bob', 'f2e'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/pqe-in-the-wild-math',
                component: ComponentCreator('/doc/docs/whitepaper/pqe-in-the-wild-math', 'f34'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/pqe-zk-together',
                component: ComponentCreator('/doc/docs/whitepaper/pqe-zk-together', '890'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/security-audit',
                component: ComponentCreator('/doc/docs/whitepaper/security-audit', 'b9c'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/unit-tests',
                component: ComponentCreator('/doc/docs/whitepaper/unit-tests', '1ac'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/viable-expensive-alternative',
                component: ComponentCreator('/doc/docs/whitepaper/viable-expensive-alternative', '3cb'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/whitepaper-system',
                component: ComponentCreator('/doc/docs/whitepaper/whitepaper-system', '048'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/doc/docs/whitepaper/zk-proofs-alice-bob',
                component: ComponentCreator('/doc/docs/whitepaper/zk-proofs-alice-bob', 'b40'),
                exact: true,
                sidebar: "docsSidebar"
              }
            ]
          }
        ]
      }
    ]
  },
  {
    path: '/doc/',
    component: ComponentCreator('/doc/', '308'),
    exact: true
  },
  {
    path: '*',
    component: ComponentCreator('*'),
  },
];

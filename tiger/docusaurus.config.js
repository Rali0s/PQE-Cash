// @ts-check

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Tiger Docs',
  tagline: 'BlueARC Privacy Protocol Documentation',
  favicon: 'img/bluearc-tiger-logo.png',
  url: 'https://bluearc.up.railway.app',
  baseUrl: '/doc/',
  organizationName: 'bluearc',
  projectName: 'tiger-docs',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  i18n: {
    defaultLocale: 'en',
    locales: ['en']
  },
  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: 'docs'
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css')
        }
      })
    ]
  ],
  themeConfig: /** @type {import('@docusaurus/preset-classic').ThemeConfig} */ ({
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true
    },
    navbar: {
      title: 'Tiger Docs',
      logo: {
        alt: 'BlueARC Tiger',
        src: 'img/bluearc-tiger-logo.png'
      },
      items: [
        { to: '/docs/intro', label: 'Overview', position: 'left' },
        { to: '/docs/whitepaper/pqe-alice-bob', label: 'Whitepaper', position: 'left' },
        { to: '/docs/admin/admin-handover', label: 'Admin', position: 'left' },
        { to: '/docs/legacy/relayer-api', label: 'Legacy', position: 'left' }
      ]
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            { label: 'Overview', to: '/docs/intro' },
            { label: 'Whitepaper', to: '/docs/whitepaper/whitepaper-system' },
            { label: 'Admin', to: '/docs/admin/admin-handover' }
          ]
        }
      ],
      copyright: `BlueARC Tiger Docs`
    }
  })
};

module.exports = config;

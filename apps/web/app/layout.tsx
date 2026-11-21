import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Sapphire | Assessments',
  description: 'Local assessment workspace',
  icons: { icon: '/sapphire-logo.png' },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

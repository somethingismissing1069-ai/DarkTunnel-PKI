/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#0a0a1a',
          800: '#1a1a2e',
          700: '#16213e',
          600: '#0f3460'
        },
        cyber: {
          cyan: '#00d4ff',
          purple: '#9d4edd',
          pink: '#ff006e'
        },
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444'
      },
      backdropBlur: {
        glass: '10px'
      }
    }
  },
  plugins: []
};

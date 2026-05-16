/// <reference types="vite/client" />

declare module "jspdf";
declare module "jspdf-autotable";

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_API_TARGET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

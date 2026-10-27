// Minimal typing of the jsdom API the lab renderer tests use (jsdom ships
// without types and the lab adds no dependency for them).
declare module "jsdom" {
  type LabWindow = Window & typeof globalThis;
  export interface ConstructorOptions {
    runScripts?: "dangerously" | "outside-only";
    pretendToBeVisual?: boolean;
    beforeParse?(window: LabWindow): void;
  }
  export class JSDOM {
    constructor(html?: string, options?: ConstructorOptions);
    readonly window: LabWindow;
  }
}

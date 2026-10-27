// Types of shots-paths.mjs (used by the tests).
export declare const MARKER: string;
export declare function isInside(parent: string, child: string): boolean;
export declare function allowedRoots(extRoot: string): string[];
export declare function checkOutDir(out: string, extRoot: string): string | null;
export declare function prepareSite(out: string): string;
export declare function servedPath(site: string, pathname: string): string | null;

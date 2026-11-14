// The only file that imports jsQR (Apache-2.0). It reads a QR code from raw RGBA pixels:
// the caller draws the page's image, canvas or screenshot into an ImageData first.
import jsQR from "jsqr";

/** The text of the QR code in the image, or null when there is none (inverted codes too). */
export function decodeQr(image: { data: Uint8ClampedArray; width: number; height: number }): string | null {
  const found = jsQR(image.data, image.width, image.height, { inversionAttempts: "attemptBoth" });
  return found ? found.data : null;
}

// Demonyms of the countries a nationality field most often lists (forms
// coverage, spec section 8, ruling R8): EU, GB, CH, NO, IS, US, CA, MX, BR, AR,
// JP, CN, IN, AU, MA, DZ, TN, SN, in fr, en, de, es, it, pt, nl, masculine and
// feminine forms ("masc/fem", one form when both are the same). German lists
// show the adjective ("Deutsch"); its nouns are read too. A word two countries
// share is dropped from the reading table (never guessed).
import { fold } from "./fold";

const TABLE: Readonly<Record<string, string>> = {
  fr: "AT Autrichien/Autrichienne;BE Belge;BG Bulgare;HR Croate;CY Chypriote;CZ Tchèque;DK Danois/Danoise;EE Estonien/Estonienne;FI Finlandais/Finlandaise;FR Français/Française;DE Allemand/Allemande;GR Grec/Grecque;HU Hongrois/Hongroise;IE Irlandais/Irlandaise;IT Italien/Italienne;LV Letton/Lettonne;LT Lituanien/Lituanienne;LU Luxembourgeois/Luxembourgeoise;MT Maltais/Maltaise;NL Néerlandais/Néerlandaise;PL Polonais/Polonaise;PT Portugais/Portugaise;RO Roumain/Roumaine;SK Slovaque;SI Slovène;ES Espagnol/Espagnole;SE Suédois/Suédoise;GB Britannique;CH Suisse;NO Norvégien/Norvégienne;IS Islandais/Islandaise;US Américain/Américaine;CA Canadien/Canadienne;MX Mexicain/Mexicaine;BR Brésilien/Brésilienne;AR Argentin/Argentine;JP Japonais/Japonaise;CN Chinois/Chinoise;IN Indien/Indienne;AU Australien/Australienne;MA Marocain/Marocaine;DZ Algérien/Algérienne;TN Tunisien/Tunisienne;SN Sénégalais/Sénégalaise",
  en: "AT Austrian;BE Belgian;BG Bulgarian;HR Croatian;CY Cypriot;CZ Czech;DK Danish;EE Estonian;FI Finnish;FR French;DE German;GR Greek;HU Hungarian;IE Irish;IT Italian;LV Latvian;LT Lithuanian;LU Luxembourgish;MT Maltese;NL Dutch;PL Polish;PT Portuguese;RO Romanian;SK Slovak;SI Slovenian;ES Spanish;SE Swedish;GB British;CH Swiss;NO Norwegian;IS Icelandic;US American;CA Canadian;MX Mexican;BR Brazilian;AR Argentine;JP Japanese;CN Chinese;IN Indian;AU Australian;MA Moroccan;DZ Algerian;TN Tunisian;SN Senegalese",
  de: "AT Österreichisch;BE Belgisch;BG Bulgarisch;HR Kroatisch;CY Zyprisch;CZ Tschechisch;DK Dänisch;EE Estnisch;FI Finnisch;FR Französisch;DE Deutsch;GR Griechisch;HU Ungarisch;IE Irisch;IT Italienisch;LV Lettisch;LT Litauisch;LU Luxemburgisch;MT Maltesisch;NL Niederländisch;PL Polnisch;PT Portugiesisch;RO Rumänisch;SK Slowakisch;SI Slowenisch;ES Spanisch;SE Schwedisch;GB Britisch;CH Schweizerisch;NO Norwegisch;IS Isländisch;US Amerikanisch;CA Kanadisch;MX Mexikanisch;BR Brasilianisch;AR Argentinisch;JP Japanisch;CN Chinesisch;IN Indisch;AU Australisch;MA Marokkanisch;DZ Algerisch;TN Tunesisch;SN Senegalesisch",
  es: "AT Austriaco/Austriaca;BE Belga;BG Búlgaro/Búlgara;HR Croata;CY Chipriota;CZ Checo/Checa;DK Danés/Danesa;EE Estonio/Estonia;FI Finlandés/Finlandesa;FR Francés/Francesa;DE Alemán/Alemana;GR Griego/Griega;HU Húngaro/Húngara;IE Irlandés/Irlandesa;IT Italiano/Italiana;LV Letón/Letona;LT Lituano/Lituana;LU Luxemburgués/Luxemburguesa;MT Maltés/Maltesa;NL Neerlandés/Neerlandesa;PL Polaco/Polaca;PT Portugués/Portuguesa;RO Rumano/Rumana;SK Eslovaco/Eslovaca;SI Esloveno/Eslovena;ES Español/Española;SE Sueco/Sueca;GB Británico/Británica;CH Suizo/Suiza;NO Noruego/Noruega;IS Islandés/Islandesa;US Estadounidense;CA Canadiense;MX Mexicano/Mexicana;BR Brasileño/Brasileña;AR Argentino/Argentina;JP Japonés/Japonesa;CN Chino/China;IN Indio/India;AU Australiano/Australiana;MA Marroquí;DZ Argelino/Argelina;TN Tunecino/Tunecina;SN Senegalés/Senegalesa",
  it: "AT Austriaco/Austriaca;BE Belga;BG Bulgaro/Bulgara;HR Croato/Croata;CY Cipriota;CZ Ceco/Ceca;DK Danese;EE Estone;FI Finlandese;FR Francese;DE Tedesco/Tedesca;GR Greco/Greca;HU Ungherese;IE Irlandese;IT Italiano/Italiana;LV Lettone;LT Lituano/Lituana;LU Lussemburghese;MT Maltese;NL Olandese;PL Polacco/Polacca;PT Portoghese;RO Rumeno/Rumena;SK Slovacco/Slovacca;SI Sloveno/Slovena;ES Spagnolo/Spagnola;SE Svedese;GB Britannico/Britannica;CH Svizzero/Svizzera;NO Norvegese;IS Islandese;US Statunitense;CA Canadese;MX Messicano/Messicana;BR Brasiliano/Brasiliana;AR Argentino/Argentina;JP Giapponese;CN Cinese;IN Indiano/Indiana;AU Australiano/Australiana;MA Marocchino/Marocchina;DZ Algerino/Algerina;TN Tunisino/Tunisina;SN Senegalese",
  pt: "AT Austríaco/Austríaca;BE Belga;BG Búlgaro/Búlgara;HR Croata;CY Cipriota;CZ Checo/Checa;DK Dinamarquês/Dinamarquesa;EE Estónio/Estónia;FI Finlandês/Finlandesa;FR Francês/Francesa;DE Alemão/Alemã;GR Grego/Grega;HU Húngaro/Húngara;IE Irlandês/Irlandesa;IT Italiano/Italiana;LV Letão/Letã;LT Lituano/Lituana;LU Luxemburguês/Luxemburguesa;MT Maltês/Maltesa;NL Neerlandês/Neerlandesa;PL Polaco/Polaca;PT Português/Portuguesa;RO Romeno/Romena;SK Eslovaco/Eslovaca;SI Esloveno/Eslovena;ES Espanhol/Espanhola;SE Sueco/Sueca;GB Britânico/Britânica;CH Suíço/Suíça;NO Norueguês/Norueguesa;IS Islandês/Islandesa;US Americano/Americana;CA Canadiano/Canadiana;MX Mexicano/Mexicana;BR Brasileiro/Brasileira;AR Argentino/Argentina;JP Japonês/Japonesa;CN Chinês/Chinesa;IN Indiano/Indiana;AU Australiano/Australiana;MA Marroquino/Marroquina;DZ Argelino/Argelina;TN Tunisino/Tunisina;SN Senegalês/Senegalesa",
  nl: "AT Oostenrijks/Oostenrijkse;BE Belgisch/Belgische;BG Bulgaars/Bulgaarse;HR Kroatisch/Kroatische;CY Cypriotisch/Cypriotische;CZ Tsjechisch/Tsjechische;DK Deens/Deense;EE Ests/Estse;FI Fins/Finse;FR Frans/Franse;DE Duits/Duitse;GR Grieks/Griekse;HU Hongaars/Hongaarse;IE Iers/Ierse;IT Italiaans/Italiaanse;LV Lets/Letse;LT Litouws/Litouwse;LU Luxemburgs/Luxemburgse;MT Maltees/Maltese;NL Nederlands/Nederlandse;PL Pools/Poolse;PT Portugees/Portugese;RO Roemeens/Roemeense;SK Slowaaks/Slowaakse;SI Sloveens/Sloveense;ES Spaans/Spaanse;SE Zweeds/Zweedse;GB Brits/Britse;CH Zwitsers/Zwitserse;NO Noors/Noorse;IS IJslands/IJslandse;US Amerikaans/Amerikaanse;CA Canadees/Canadese;MX Mexicaans/Mexicaanse;BR Braziliaans/Braziliaanse;AR Argentijns/Argentijnse;JP Japans/Japanse;CN Chinees/Chinese;IN Indiaas/Indiase;AU Australisch/Australische;MA Marokkaans/Marokkaanse;DZ Algerijns/Algerijnse;TN Tunesisch/Tunesische;SN Senegalees/Senegalese",
};

/** Read only: other common forms (nouns, older names). */
const ALSO: Readonly<Record<string, string>> = {
  DE: "Deutscher Deutsche Allemande",
  FR: "Franzose Französin",
  AT: "Österreicher Österreicherin",
  CH: "Schweizer Schweizerin",
  US: "US-amerikanisch Estadunidense Norte-americano Norte-americana Americano Americana Statunitense",
  NL: "Holländisch Holandés Holandesa Holandês Holandesa Neerlandese",
  CA: "Canadense",
  PL: "Polonês Polonesa",
  EE: "Estoniano Estoniana Estonien",
  LU: "Luxembourger",
  SI: "Slovene",
  AR: "Argentinian",
  GB: "English Anglais Anglaise",
};

const FORMS = new Map<string, Map<string, [string, string]>>();
const READ = new Map<string, string | null>();
{
  const add = (word: string, cc: string) => {
    const k = fold(word);
    if (k === "") return;
    const had = READ.get(k);
    READ.set(k, had === undefined || had === cc ? cc : null);
  };
  for (const [lang, rows] of Object.entries(TABLE)) {
    const m = new Map<string, [string, string]>();
    for (const row of rows.split(";")) {
      const [cc, forms] = [row.slice(0, 2), row.slice(3)];
      const [masc, fem] = forms.split("/");
      m.set(cc, [masc!, fem ?? masc!]);
      add(masc!, cc);
      add(fem ?? masc!, cc);
    }
    FORMS.set(lang, m);
  }
  for (const [cc, words] of Object.entries(ALSO)) for (const w of words.split(" ")) add(w, cc);
}

/** Alpha-2 country a demonym names in any of the seven languages ("Française", "Deutsch"), or null. */
export function demonymCountry(text: string): string | null {
  const t = text.replace(/\((?:e|a|ne|se|in)\)/gi, "").trim();
  return READ.get(fold(t)) ?? null;
}

/** The demonym of `cc` in `lang` (feminine when asked and the language has one), or null. */
export function demonym(cc: string, lang: string, feminine = false): string | null {
  const l = lang.toLowerCase().split(/[-_]/)[0] ?? "";
  const f = FORMS.get(l)?.get(cc.toUpperCase());
  if (!f) return null;
  return feminine ? f[1] : f[0];
}

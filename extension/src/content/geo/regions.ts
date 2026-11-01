// Embedded subdivision table (ISO 3166-2) for the countries whose checkout
// forms most often ask for a state: United States (states, DC, territories),
// Canada (provinces, territories), France (regions, departments, overseas
// departments), Germany (Länder). Each row: code, names (the first is the
// local one), abbreviations people write. Kept compact: one string per row,
// "CODE|name;name|abbr;abbr".
import { squash } from "./fold";

const ROWS = `US-AL|Alabama|Ala.
US-AK|Alaska|
US-AZ|Arizona|Ariz.
US-AR|Arkansas|Ark.
US-CA|California;Californie|Calif.;Cal.
US-CO|Colorado|Colo.;Col.
US-CT|Connecticut|Conn.
US-DE|Delaware|Del.
US-DC|District of Columbia;Washington DC;District de Columbia|D.C.
US-FL|Florida;Floride|Fla.;Flor.
US-GA|Georgia;Géorgie|Ga.
US-HI|Hawaii;Hawaï|
US-ID|Idaho|Ida.
US-IL|Illinois|Ill.
US-IN|Indiana|Ind.
US-IA|Iowa|
US-KS|Kansas|Kan.;Kans.
US-KY|Kentucky|Ky.
US-LA|Louisiana;Louisiane|La.
US-ME|Maine|Me.
US-MD|Maryland|Md.
US-MA|Massachusetts|Mass.
US-MI|Michigan|Mich.
US-MN|Minnesota|Minn.
US-MS|Mississippi|Miss.
US-MO|Missouri|Mo.
US-MT|Montana|Mont.
US-NE|Nebraska|Neb.;Nebr.
US-NV|Nevada|Nev.
US-NH|New Hampshire|N.H.
US-NJ|New Jersey|N.J.
US-NM|New Mexico;Nouveau-Mexique|N.M.;N.Mex.
US-NY|New York;État de New York|N.Y.
US-NC|North Carolina;Caroline du Nord|N.C.
US-ND|North Dakota;Dakota du Nord|N.D.;N.Dak.
US-OH|Ohio|
US-OK|Oklahoma|Okla.
US-OR|Oregon|Ore.;Oreg.
US-PA|Pennsylvania;Pennsylvanie|Pa.;Penn.;Penna.
US-RI|Rhode Island|R.I.
US-SC|South Carolina;Caroline du Sud|S.C.
US-SD|South Dakota;Dakota du Sud|S.D.;S.Dak.
US-TN|Tennessee|Tenn.
US-TX|Texas|Tex.
US-UT|Utah|
US-VT|Vermont|Vt.
US-VA|Virginia;Virginie|Va.
US-WA|Washington;État de Washington|Wash.
US-WV|West Virginia;Virginie-Occidentale|W.Va.;W.Virg.
US-WI|Wisconsin|Wis.;Wisc.
US-WY|Wyoming|Wyo.
US-AS|American Samoa;Samoa américaines|
US-GU|Guam|
US-MP|Northern Mariana Islands;Îles Mariannes du Nord|
US-PR|Puerto Rico;Porto Rico|P.R.
US-UM|United States Minor Outlying Islands;U.S. Minor Outlying Islands|
US-VI|U.S. Virgin Islands;United States Virgin Islands;Virgin Islands;Îles Vierges des États-Unis|V.I.;USVI
CA-AB|Alberta|Alta.;Alb.
CA-BC|British Columbia;Colombie-Britannique|B.C.;C.-B.
CA-MB|Manitoba|Man.
CA-NB|New Brunswick;Nouveau-Brunswick|N.B.
CA-NL|Newfoundland and Labrador;Terre-Neuve-et-Labrador;Newfoundland;Terre-Neuve|Nfld.;NF;T.-N.-L.
CA-NS|Nova Scotia;Nouvelle-Écosse|N.S.;N.-É.
CA-NT|Northwest Territories;Territoires du Nord-Ouest|N.W.T.;T.N.-O.
CA-NU|Nunavut|Nvt.
CA-ON|Ontario|Ont.
CA-PE|Prince Edward Island;Île-du-Prince-Édouard|P.E.I.;Î.-P.-É.
CA-QC|Québec;Quebec|Que.;Qué.;PQ;P.Q.
CA-SK|Saskatchewan|Sask.
CA-YT|Yukon;Yukon Territory|Y.T.;Yuk.;YK
DE-BW|Baden-Württemberg|BaWü
DE-BY|Bayern;Bavaria;Bavière|Bay.
DE-BE|Berlin|
DE-BB|Brandenburg;Brandebourg|Bbg.
DE-HB|Bremen;Brême|
DE-HH|Hamburg;Hambourg|
DE-HE|Hessen;Hesse|
DE-MV|Mecklenburg-Vorpommern;Mecklenburg-Western Pomerania;Mecklembourg-Poméranie-Occidentale|M-V
DE-NI|Niedersachsen;Lower Saxony;Basse-Saxe|Nds.
DE-NW|Nordrhein-Westfalen;North Rhine-Westphalia;Rhénanie-du-Nord-Westphalie|NRW
DE-RP|Rheinland-Pfalz;Rhineland-Palatinate;Rhénanie-Palatinat|RLP
DE-SL|Saarland;Sarre|
DE-SN|Sachsen;Saxony;Saxe|
DE-ST|Sachsen-Anhalt;Saxony-Anhalt;Saxe-Anhalt|LSA
DE-SH|Schleswig-Holstein|
DE-TH|Thüringen;Thuringia;Thuringe|
FR-ARA|Auvergne-Rhône-Alpes|AURA
FR-BFC|Bourgogne-Franche-Comté|
FR-BRE|Bretagne;Brittany|
FR-CVL|Centre-Val de Loire;Centre|
FR-20R|Corse;Corsica|COR
FR-GES|Grand Est|
FR-HDF|Hauts-de-France|
FR-IDF|Île-de-France|
FR-NOR|Normandie;Normandy|
FR-NAQ|Nouvelle-Aquitaine|
FR-OCC|Occitanie|
FR-PDL|Pays de la Loire|
FR-PAC|Provence-Alpes-Côte d'Azur|PACA
FR-971|Guadeloupe|
FR-972|Martinique|
FR-973|Guyane;Guyane française;French Guiana|
FR-974|La Réunion;Réunion|
FR-976|Mayotte|`;

// French departments, by region: "REGION:dept=name,dept=name".
const DEPARTMENTS = `ARA:01=Ain,03=Allier,07=Ardèche,15=Cantal,26=Drôme,38=Isère,42=Loire,43=Haute-Loire,63=Puy-de-Dôme,69=Rhône,73=Savoie,74=Haute-Savoie
BFC:21=Côte-d'Or,25=Doubs,39=Jura,58=Nièvre,70=Haute-Saône,71=Saône-et-Loire,89=Yonne,90=Territoire de Belfort
BRE:22=Côtes-d'Armor,29=Finistère,35=Ille-et-Vilaine,56=Morbihan
CVL:18=Cher,28=Eure-et-Loir,36=Indre,37=Indre-et-Loire,41=Loir-et-Cher,45=Loiret
20R:2A=Corse-du-Sud,2B=Haute-Corse
GES:08=Ardennes,10=Aube,51=Marne,52=Haute-Marne,54=Meurthe-et-Moselle,55=Meuse,57=Moselle,67=Bas-Rhin,68=Haut-Rhin,88=Vosges
HDF:02=Aisne,59=Nord,60=Oise,62=Pas-de-Calais,80=Somme
IDF:75=Paris,77=Seine-et-Marne,78=Yvelines,91=Essonne,92=Hauts-de-Seine,93=Seine-Saint-Denis,94=Val-de-Marne,95=Val-d'Oise
NOR:14=Calvados,27=Eure,50=Manche,61=Orne,76=Seine-Maritime
NAQ:16=Charente,17=Charente-Maritime,19=Corrèze,23=Creuse,24=Dordogne,33=Gironde,40=Landes,47=Lot-et-Garonne,64=Pyrénées-Atlantiques,79=Deux-Sèvres,86=Vienne,87=Haute-Vienne
OCC:09=Ariège,11=Aude,12=Aveyron,30=Gard,31=Haute-Garonne,32=Gers,34=Hérault,46=Lot,48=Lozère,65=Hautes-Pyrénées,66=Pyrénées-Orientales,81=Tarn,82=Tarn-et-Garonne
PDL:44=Loire-Atlantique,49=Maine-et-Loire,53=Mayenne,72=Sarthe,85=Vendée
PAC:04=Alpes-de-Haute-Provence,05=Hautes-Alpes,06=Alpes-Maritimes,13=Bouches-du-Rhône,83=Var,84=Vaucluse`;

/** Extra keys of a department: the ISO collectivity code of Paris. */
const DEPT_ALIASES: Readonly<Record<string, string[]>> = { "75": ["75C"] };

export interface Region {
  /** ISO 3166-2, "US-CA". */
  code: string;
  names: readonly string[];
  abbr: readonly string[];
}

const PARENT = new Map<string, string>();

export const REGIONS: readonly Region[] = (() => {
  const out: Region[] = [];
  for (const row of ROWS.split("\n")) {
    const [code = "", names = "", abbr = ""] = row.split("|");
    out.push({ code, names: names.split(";").filter(Boolean), abbr: abbr.split(";").filter(Boolean) });
  }
  for (const line of DEPARTMENTS.split("\n")) {
    const [region = "", list = ""] = line.split(":");
    for (const item of list.split(",")) {
      const [num = "", name = ""] = item.split("=");
      const code = `FR-${num}`;
      out.push({ code, names: [name], abbr: DEPT_ALIASES[num] ?? [] });
      PARENT.set(code, `FR-${region}`);
    }
  }
  return out;
})();

const BY_CODE = new Map(REGIONS.map((r) => [r.code, r]));

/** Squashed key to the codes it may name. */
const INDEX = (() => {
  const m = new Map<string, Set<string>>();
  const add = (key: string, code: string) => {
    if (key === "") return;
    let s = m.get(key);
    if (!s) m.set(key, (s = new Set()));
    s.add(code);
  };
  for (const r of REGIONS) {
    const suffix = r.code.slice(3);
    add(squash(r.code), r.code);
    add(squash(suffix), r.code);
    // "01" is also written "1".
    if (/^0\d$/.test(suffix)) add(suffix.slice(1), r.code);
    for (const n of r.names) add(squash(n), r.code);
    for (const a of r.abbr) add(squash(a), r.code);
  }
  return m;
})();

const CANONICAL = /^([A-Za-z]{2})-([A-Za-z0-9]{1,3})$/;
const SEPARATORS = /\s[-–:|/]\s|[()[\],]/;

function lookup(part: string, country: string | null): Set<string> {
  const all = INDEX.get(squash(part));
  if (!all) return new Set();
  if (country === null) return all;
  return new Set([...all].filter((c) => c.startsWith(`${country}-`)));
}

/**
 * The region codes `raw` may name, within `country` (alpha-2) when known,
 * sorted. "75 - Paris" is read part by part: every part must name the same
 * region. Empty when nothing (or no common region) is found.
 */
export function resolveRegion(raw: string, country: string | null): string[] {
  const t = raw.trim();
  if (t === "") return [];
  const canon = CANONICAL.exec(t);
  if (canon) {
    const code = `${canon[1]!.toUpperCase()}-${canon[2]!.toUpperCase()}`;
    if (BY_CODE.has(code)) return country === null || code.startsWith(`${country}-`) ? [code] : [];
  }
  const whole = lookup(t, country);
  if (whole.size > 0) return [...whole].sort();
  const parts = t.split(SEPARATORS).map((p) => p.trim()).filter((p) => squash(p) !== "");
  if (parts.length < 2) return [];
  let common = lookup(parts[0]!, country);
  for (const p of parts.slice(1)) {
    const s = lookup(p, country);
    common = new Set([...common].filter((c) => s.has(c)));
  }
  return [...common].sort();
}

/** The region a French department belongs to, else null. */
export function parentRegion(code: string): string | null {
  return PARENT.get(code) ?? null;
}

/**
 * How a canonical region is written in a free text field: the postal
 * abbreviation in the United States and Canada, the local name elsewhere.
 * Anything that is not a canonical code of the table is kept as it is.
 */
export function regionText(v: string): string {
  const canon = CANONICAL.exec(v.trim());
  const r = canon ? BY_CODE.get(`${canon[1]!.toUpperCase()}-${canon[2]!.toUpperCase()}`) : undefined;
  if (!r) return v;
  if (r.code.startsWith("US-") || r.code.startsWith("CA-")) return r.code.slice(3);
  return r.names[0] ?? v;
}

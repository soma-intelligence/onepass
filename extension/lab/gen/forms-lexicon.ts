// Labels of the forms flows of the autofill lab (travel booking, company,
// car rental, admin identity), written by hand for the lab and never derived
// from the extension's lexicon (src/content/detect/lexicon.ts): the lab must
// not grade the extension with its own words. Each role has, per label
// language, full labels and at least one abbreviated one ("N° passeport",
// "Pass-Nr.", "Nº pasaporte"), as real pages write them.
import type { FormsRole, Lang } from "./model.ts";

/** Label languages of the forms flows (the site languages of generator version 3). */
export const FORMS_LANGS = ["fr", "en", "de", "es", "it", "pt", "nl"] as const;
export type FormsLang = (typeof FORMS_LANGS)[number];

/** Labels of one role in one language: full ones and abbreviated ones (at least one of each kind). */
export interface Labels { full: string[]; short: string[] }

type ByLang = Record<FormsLang, Labels>;
const L = (full: string[], short: string[]): Labels => ({ full, short });

export const FORMS_LABELS: Record<FormsRole, ByLang> = {
  honorific: {
    fr: L(["Civilité", "Titre de civilité"], ["Civ."]),
    en: L(["Title", "Salutation"], ["Title (Mr/Ms)"]),
    de: L(["Anrede", "Ihre Anrede"], ["Anr."]),
    es: L(["Tratamiento", "Título"], ["Trat."]),
    it: L(["Titolo", "Appellativo"], ["Tit."]),
    pt: L(["Tratamento", "Título"], ["Trat."]),
    nl: L(["Aanhef", "Uw aanhef"], ["Aanh."]),
  },
  additional_name: {
    fr: L(["Deuxième prénom", "Autres prénoms"], ["2e prénom"]),
    en: L(["Middle name", "Middle names"], ["M.I."]),
    de: L(["Zweiter Vorname", "Weitere Vornamen"], ["2. Vorname"]),
    es: L(["Segundo nombre", "Otros nombres"], ["2º nombre"]),
    it: L(["Secondo nome", "Altri nomi"], ["2° nome"]),
    pt: L(["Nome do meio", "Segundo nome"], ["2º nome"]),
    nl: L(["Tweede voornaam", "Overige voornamen"], ["2e voornaam"]),
  },
  birth_name: {
    fr: L(["Nom de naissance", "Nom de jeune fille"], ["Nom naiss."]),
    en: L(["Birth name", "Maiden name", "Surname at birth"], ["Birth surname"]),
    de: L(["Geburtsname", "Name bei Geburt"], ["Geb.-Name"]),
    es: L(["Apellido de nacimiento", "Apellido de soltera"], ["Apell. nac."]),
    it: L(["Cognome di nascita", "Cognome da nubile"], ["Cogn. nascita"]),
    pt: L(["Nome de nascimento", "Apelido de solteira"], ["Nome nasc."]),
    nl: L(["Geboortenaam", "Meisjesnaam"], ["Geb. naam"]),
  },
  sex: {
    fr: L(["Sexe", "Genre"], ["Sexe (H/F)"]),
    en: L(["Sex", "Gender"], ["Sex (M/F)"]),
    de: L(["Geschlecht", "Ihr Geschlecht"], ["Geschl."]),
    es: L(["Sexo", "Género"], ["Sexo (H/M)"]),
    it: L(["Sesso", "Genere"], ["Sesso (M/F)"]),
    pt: L(["Sexo", "Género"], ["Sexo (M/F)"]),
    nl: L(["Geslacht", "Uw geslacht"], ["Geslacht (M/V)"]),
  },
  birth_place: {
    fr: L(["Lieu de naissance", "Ville de naissance", "Commune de naissance"], ["Né(e) à"]),
    en: L(["Place of birth", "City of birth"], ["Birthplace"]),
    de: L(["Geburtsort", "Ort der Geburt"], ["Geb.-Ort"]),
    es: L(["Lugar de nacimiento", "Ciudad de nacimiento"], ["Lugar nac."]),
    it: L(["Luogo di nascita", "Comune di nascita"], ["Nato/a a"]),
    pt: L(["Local de nascimento", "Naturalidade"], ["Local nasc."]),
    nl: L(["Geboorteplaats", "Plaats van geboorte"], ["Geb. plaats"]),
  },
  birth_country: {
    fr: L(["Pays de naissance", "Pays où vous êtes né(e)"], ["Pays naiss."]),
    en: L(["Country of birth", "Birth country"], ["Birth ctry"]),
    de: L(["Geburtsland", "Land der Geburt"], ["Geb.-Land"]),
    es: L(["País de nacimiento", "País natal"], ["País nac."]),
    it: L(["Paese di nascita", "Stato di nascita"], ["Paese nasc."]),
    pt: L(["País de nascimento", "País natal"], ["País nasc."]),
    nl: L(["Geboorteland", "Land van geboorte"], ["Geb. land"]),
  },
  nationality: {
    fr: L(["Nationalité", "Citoyenneté"], ["Nat."]),
    en: L(["Nationality", "Citizenship"], ["Nat."]),
    de: L(["Staatsangehörigkeit", "Nationalität"], ["Staatsang."]),
    es: L(["Nacionalidad", "Ciudadanía"], ["Nac."]),
    it: L(["Nazionalità", "Cittadinanza"], ["Naz."]),
    pt: L(["Nacionalidade", "Cidadania"], ["Nac."]),
    nl: L(["Nationaliteit", "Staatsburgerschap"], ["Nat."]),
  },
  bday_day: {
    fr: L(["Jour", "Jour de naissance"], ["JJ"]),
    en: L(["Day", "Birth day"], ["DD"]),
    de: L(["Tag", "Geburtstag (Tag)"], ["TT"]),
    es: L(["Día", "Día de nacimiento"], ["DD"]),
    it: L(["Giorno", "Giorno di nascita"], ["GG"]),
    pt: L(["Dia", "Dia de nascimento"], ["DD"]),
    nl: L(["Dag", "Geboortedag"], ["DD"]),
  },
  bday_month: {
    fr: L(["Mois", "Mois de naissance"], ["MM"]),
    en: L(["Month", "Birth month"], ["MM"]),
    de: L(["Monat", "Geburtsmonat"], ["MM"]),
    es: L(["Mes", "Mes de nacimiento"], ["MM"]),
    it: L(["Mese", "Mese di nascita"], ["MM"]),
    pt: L(["Mês", "Mês de nascimento"], ["MM"]),
    nl: L(["Maand", "Geboortemaand"], ["MM"]),
  },
  bday_year: {
    fr: L(["Année", "Année de naissance"], ["AAAA"]),
    en: L(["Year", "Birth year"], ["YYYY"]),
    de: L(["Jahr", "Geburtsjahr"], ["JJJJ"]),
    es: L(["Año", "Año de nacimiento"], ["AAAA"]),
    it: L(["Anno", "Anno di nascita"], ["AAAA"]),
    pt: L(["Ano", "Ano de nascimento"], ["AAAA"]),
    nl: L(["Jaar", "Geboortejaar"], ["JJJJ"]),
  },
  passport_number: {
    fr: L(["Numéro de passeport", "Passeport (numéro)"], ["N° passeport"]),
    en: L(["Passport number", "Passport no."], ["Passport #"]),
    de: L(["Reisepassnummer", "Passnummer"], ["Pass-Nr."]),
    es: L(["Número de pasaporte", "Pasaporte (número)"], ["Nº pasaporte"]),
    it: L(["Numero di passaporto", "Passaporto (numero)"], ["N. passaporto"]),
    pt: L(["Número do passaporte", "Passaporte (número)"], ["Nº passaporte"]),
    nl: L(["Paspoortnummer", "Nummer van het paspoort"], ["Paspoortnr."]),
  },
  passport_issuing_country: {
    fr: L(["Pays de délivrance", "Pays émetteur du passeport"], ["Pays émetteur"]),
    en: L(["Issuing country", "Country of issue"], ["Issued by"]),
    de: L(["Ausstellungsland", "Ausstellender Staat"], ["Ausst.-Land"]),
    es: L(["País de expedición", "País emisor del pasaporte"], ["País emisor"]),
    it: L(["Paese di rilascio", "Stato di rilascio"], ["Rilasciato da"]),
    pt: L(["País emissor", "País de emissão"], ["Emitido por"]),
    nl: L(["Land van afgifte", "Uitgegeven door (land)"], ["Afgifteland"]),
  },
  passport_issue_date: {
    fr: L(["Date de délivrance", "Délivré le"], ["Délivr."]),
    en: L(["Date of issue", "Issue date"], ["Issued"]),
    de: L(["Ausstellungsdatum", "Ausgestellt am"], ["Ausst.-Datum"]),
    es: L(["Fecha de expedición", "Fecha de emisión"], ["F. expedición"]),
    it: L(["Data di rilascio", "Data di emissione"], ["Rilascio"]),
    pt: L(["Data de emissão", "Emitido em"], ["Dt. emissão"]),
    nl: L(["Afgiftedatum", "Datum van afgifte"], ["Afgegeven"]),
  },
  passport_expiry: {
    fr: L(["Date d'expiration", "Valable jusqu'au"], ["Exp."]),
    en: L(["Expiry date", "Expiration date", "Valid until"], ["Exp."]),
    de: L(["Ablaufdatum", "Gültig bis"], ["Gült. bis"]),
    es: L(["Fecha de caducidad", "Fecha de vencimiento"], ["Cad."]),
    it: L(["Data di scadenza", "Valido fino al"], ["Scad."]),
    pt: L(["Data de validade", "Válido até"], ["Val."]),
    nl: L(["Vervaldatum", "Geldig tot"], ["Geldig t/m"]),
  },
  loyalty_number: {
    fr: L(["Numéro de fidélité", "Numéro grand voyageur", "Carte de fidélité"], ["N° fidélité"]),
    en: L(["Frequent flyer number", "Loyalty number", "Rewards number"], ["FF no."]),
    de: L(["Vielfliegernummer", "Bonusnummer", "Kundenkartennummer"], ["Bonus-Nr."]),
    es: L(["Número de viajero frecuente", "Número de socio"], ["Nº socio"]),
    it: L(["Numero frequent flyer", "Codice fedeltà", "Numero socio"], ["N. socio"]),
    pt: L(["Número de passageiro frequente", "Número de fidelidade"], ["Nº fidelidade"]),
    nl: L(["Frequent flyer nummer", "Lidmaatschapsnummer"], ["Lidnr."]),
  },
  license_number: {
    fr: L(["Numéro de permis", "Numéro du permis de conduire"], ["N° permis"]),
    en: L(["Driver's license number", "Driving licence number", "Licence number"], ["DL #"]),
    de: L(["Führerscheinnummer", "Nummer des Führerscheins"], ["Führerschein-Nr."]),
    es: L(["Número de permiso de conducir", "Número de carné de conducir"], ["Nº carné"]),
    it: L(["Numero di patente", "Patente di guida (numero)"], ["N. patente"]),
    pt: L(["Número da carta de condução", "Carta de condução (número)"], ["Nº carta"]),
    nl: L(["Rijbewijsnummer", "Nummer van het rijbewijs"], ["Rijbewijsnr."]),
  },
  license_issuing_country: {
    fr: L(["Pays de délivrance du permis", "Pays émetteur du permis"], ["Pays permis"]),
    en: L(["License issuing country", "Country of issue of the licence"], ["DL country"]),
    de: L(["Ausstellungsland des Führerscheins", "Führerschein ausgestellt in"], ["FS-Land"]),
    es: L(["País de expedición del permiso", "País emisor del carné"], ["País carné"]),
    it: L(["Paese di rilascio della patente", "Patente rilasciata in"], ["Paese patente"]),
    pt: L(["País emissor da carta", "País de emissão da carta"], ["País carta"]),
    nl: L(["Land van afgifte rijbewijs", "Rijbewijs afgegeven in"], ["Land rijbewijs"]),
  },
  license_issue_date: {
    fr: L(["Date de délivrance du permis", "Permis délivré le"], ["Délivr. permis"]),
    en: L(["License issue date", "Licence date of issue"], ["DL issued"]),
    de: L(["Ausstellungsdatum des Führerscheins", "Führerschein ausgestellt am"], ["FS ausgest."]),
    es: L(["Fecha de expedición del permiso", "Carné expedido el"], ["F. exp. carné"]),
    it: L(["Data di rilascio della patente", "Patente rilasciata il"], ["Ril. patente"]),
    pt: L(["Data de emissão da carta", "Carta emitida em"], ["Emissão carta"]),
    nl: L(["Afgiftedatum rijbewijs", "Rijbewijs afgegeven op"], ["Afgifte rijb."]),
  },
  license_expiry: {
    fr: L(["Date d'expiration du permis", "Permis valable jusqu'au"], ["Exp. permis"]),
    en: L(["License expiry date", "Licence valid until"], ["DL exp."]),
    de: L(["Führerschein gültig bis", "Ablaufdatum des Führerscheins"], ["FS gült. bis"]),
    es: L(["Fecha de caducidad del permiso", "Carné válido hasta"], ["Cad. carné"]),
    it: L(["Scadenza patente", "Patente valida fino al"], ["Scad. patente"]),
    pt: L(["Validade da carta", "Carta válida até"], ["Val. carta"]),
    nl: L(["Vervaldatum rijbewijs", "Rijbewijs geldig tot"], ["Rijb. geldig t/m"]),
  },
  job_title: {
    fr: L(["Poste", "Fonction", "Intitulé du poste"], ["Fonct."]),
    en: L(["Job title", "Position"], ["Title/role"]),
    de: L(["Position", "Berufsbezeichnung", "Funktion"], ["Pos."]),
    es: L(["Cargo", "Puesto"], ["Cargo/puesto"]),
    it: L(["Ruolo", "Posizione", "Qualifica"], ["Qualif."]),
    pt: L(["Cargo", "Função"], ["Cargo/função"]),
    nl: L(["Functie", "Functietitel"], ["Funct."]),
  },
  department: {
    fr: L(["Service", "Département"], ["Serv."]),
    en: L(["Department", "Division"], ["Dept."]),
    de: L(["Abteilung", "Bereich"], ["Abt."]),
    es: L(["Departamento", "Área"], ["Dpto."]),
    it: L(["Reparto", "Dipartimento"], ["Dip."]),
    pt: L(["Departamento", "Divisão"], ["Dep."]),
    nl: L(["Afdeling", "Divisie"], ["Afd."]),
  },
  vat_number: {
    fr: L(["Numéro de TVA", "TVA intracommunautaire"], ["N° TVA"]),
    en: L(["VAT number", "VAT registration number"], ["VAT ID"]),
    de: L(["USt-IdNr.", "Umsatzsteuer-Identifikationsnummer"], ["USt-ID"]),
    es: L(["Número de IVA", "NIF-IVA"], ["Nº IVA"]),
    it: L(["Partita IVA", "Numero di partita IVA"], ["P. IVA"]),
    pt: L(["Número de IVA", "NIF para efeitos de IVA"], ["Nº IVA"]),
    nl: L(["Btw-nummer", "Btw-identificatienummer"], ["Btw-id"]),
  },
  company_id: {
    fr: L(["SIRET", "Numéro SIRET", "Numéro d'immatriculation"], ["N° SIRET"]),
    en: L(["Company number", "Company registration number"], ["Co. reg. no."]),
    de: L(["Handelsregisternummer", "Registernummer"], ["HRB-Nr."]),
    es: L(["CIF", "Número de registro mercantil"], ["Nº CIF"]),
    it: L(["Codice fiscale azienda", "Numero REA"], ["Cod. fisc."]),
    pt: L(["NIPC", "Número de matrícula"], ["Nº NIPC"]),
    nl: L(["KvK-nummer", "Kamer van Koophandel nummer"], ["KvK"]),
  },
  website: {
    fr: L(["Site web", "Site internet"], ["Web"]),
    en: L(["Website", "Homepage"], ["Web"]),
    de: L(["Webseite", "Homepage"], ["Web"]),
    es: L(["Sitio web", "Página web"], ["Web"]),
    it: L(["Sito web", "Sito internet"], ["Web"]),
    pt: L(["Site", "Website"], ["Web"]),
    nl: L(["Website", "Webadres"], ["Web"]),
  },
  tel_work: {
    fr: L(["Téléphone professionnel", "Téléphone du bureau"], ["Tél. pro"]),
    en: L(["Work phone", "Business phone", "Office phone"], ["Work tel."]),
    de: L(["Telefon geschäftlich", "Diensttelefon"], ["Tel. gesch."]),
    es: L(["Teléfono del trabajo", "Teléfono de la oficina"], ["Tel. trabajo"]),
    it: L(["Telefono di lavoro", "Telefono ufficio"], ["Tel. uff."]),
    pt: L(["Telefone do trabalho", "Telefone profissional"], ["Tel. trab."]),
    nl: L(["Zakelijk telefoonnummer", "Werktelefoon"], ["Tel. werk"]),
  },
};

/** Whether `lang` has forms labels of its own (else English is used). */
export const isFormsLang = (lang: Lang): lang is FormsLang => (FORMS_LANGS as readonly string[]).includes(lang);

/** Every label of `role` in `lang` (English for another language), full ones first. */
export function formsLabels(role: FormsRole, lang: Lang): string[] {
  const l = FORMS_LABELS[role][isFormsLang(lang) ? lang : "en"];
  return [...l.full, ...l.short];
}

// ---- page vocabulary of the forms flows (lab's own words) ----

const pick = <T>(table: Record<FormsLang, T>, lang: Lang): T => table[isFormsLang(lang) ? lang : "en"];

/** Month names (full, then abbreviated) per language, January first. */
export const MONTH_NAMES: Record<FormsLang, { full: string[]; short: string[] }> = {
  fr: { full: ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"],
    short: ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."] },
  en: { full: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
    short: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] },
  de: { full: ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"],
    short: ["Jan.", "Feb.", "Mär.", "Apr.", "Mai", "Jun.", "Jul.", "Aug.", "Sep.", "Okt.", "Nov.", "Dez."] },
  es: { full: ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"],
    short: ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"] },
  it: { full: ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"],
    short: ["gen", "feb", "mar", "apr", "mag", "giu", "lug", "ago", "set", "ott", "nov", "dic"] },
  pt: { full: ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"],
    short: ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"] },
  nl: { full: ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"],
    short: ["jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec"] },
};
export const monthNames = (lang: Lang) => pick(MONTH_NAMES, lang);

/** Date order and separator of a site language for text dates (tokens DD, MM, YYYY). */
const DATE_FORMAT: Record<FormsLang, string> = { fr: "DD/MM/YYYY", en: "MM/DD/YYYY", de: "DD.MM.YYYY", es: "DD/MM/YYYY", it: "DD/MM/YYYY", pt: "DD/MM/YYYY", nl: "DD-MM-YYYY" };
export const dateFormatOf = (lang: Lang) => pick(DATE_FORMAT, lang);
/** The letters a page of each language writes its date placeholder with (day, month, year). */
const DATE_LETTERS: Record<FormsLang, [string, string, string]> = {
  fr: ["JJ", "MM", "AAAA"], en: ["DD", "MM", "YYYY"], de: ["TT", "MM", "JJJJ"], es: ["DD", "MM", "AAAA"],
  it: ["gg", "mm", "aaaa"], pt: ["dd", "mm", "aaaa"], nl: ["dd", "mm", "jjjj"],
};
/** The placeholder of `format` in `lang`'s letters ("DD/MM/YYYY" in French: "JJ/MM/AAAA"). */
export function datePlaceholder(format: string, lang: Lang): string {
  const [d, m, y] = pick(DATE_LETTERS, lang);
  return format.replace("YYYY", y).replace("DD", d).replace("MM", m);
}

/** Legend of passenger `n` (1-based) of a booking: several wordings per language. */
const PASSENGER: Record<FormsLang, ((n: number) => string)[]> = {
  fr: [(n) => `Passager ${n}`, (n) => `Voyageur ${n}`, (n) => `Adulte ${n}`],
  en: [(n) => `Passenger ${n}`, (n) => `Traveller ${n}`, (n) => `Adult ${n}`],
  de: [(n) => `Reisender ${n}`, (n) => `Passagier ${n}`, (n) => `Erwachsener ${n}`],
  es: [(n) => `Pasajero ${n}`, (n) => `Viajero ${n}`, (n) => `Adulto ${n}`],
  it: [(n) => `Passeggero ${n}`, (n) => `Viaggiatore ${n}`, (n) => `Adulto ${n}`],
  pt: [(n) => `Passageiro ${n}`, (n) => `Viajante ${n}`, (n) => `Adulto ${n}`],
  nl: [(n) => `Passagier ${n}`, (n) => `Reiziger ${n}`, (n) => `Volwassene ${n}`],
};
export const passengerLegends = (lang: Lang) => pick(PASSENGER, lang);

export type BlockWord = "contact" | "billing" | "shipping" | "sameAsBilling" | "driver" | "company" | "person";
const BLOCK_WORDS: Record<FormsLang, Record<BlockWord, string>> = {
  fr: { contact: "Coordonnées", billing: "Adresse de facturation", shipping: "Adresse de livraison", sameAsBilling: "Identique à l'adresse de facturation",
    driver: "Conducteur principal", company: "Votre entreprise", person: "Vos informations" },
  en: { contact: "Contact details", billing: "Billing address", shipping: "Shipping address", sameAsBilling: "Same as billing address",
    driver: "Main driver", company: "Your company", person: "Your details" },
  de: { contact: "Kontaktdaten", billing: "Rechnungsadresse", shipping: "Lieferadresse", sameAsBilling: "Wie Rechnungsadresse",
    driver: "Hauptfahrer", company: "Ihr Unternehmen", person: "Ihre Angaben" },
  es: { contact: "Datos de contacto", billing: "Dirección de facturación", shipping: "Dirección de envío", sameAsBilling: "Igual que la dirección de facturación",
    driver: "Conductor principal", company: "Su empresa", person: "Sus datos" },
  it: { contact: "Recapiti", billing: "Indirizzo di fatturazione", shipping: "Indirizzo di spedizione", sameAsBilling: "Uguale all'indirizzo di fatturazione",
    driver: "Conducente principale", company: "La tua azienda", person: "I tuoi dati" },
  pt: { contact: "Dados de contacto", billing: "Morada de faturação", shipping: "Morada de entrega", sameAsBilling: "Igual à morada de faturação",
    driver: "Condutor principal", company: "A sua empresa", person: "Os seus dados" },
  nl: { contact: "Contactgegevens", billing: "Factuuradres", shipping: "Bezorgadres", sameAsBilling: "Zelfde als factuuradres",
    driver: "Hoofdbestuurder", company: "Uw bedrijf", person: "Uw gegevens" },
};
export const blockWord = (lang: Lang, w: BlockWord) => pick(BLOCK_WORDS, lang)[w];

/** Page headings of the four flows. */
const HEADINGS: Record<FormsLang, Record<"travel_booking" | "company_b2b" | "car_rental" | "admin_identity", string>> = {
  fr: { travel_booking: "Informations passagers", company_b2b: "Compte professionnel", car_rental: "Location de voiture", admin_identity: "Demande en ligne" },
  en: { travel_booking: "Passenger details", company_b2b: "Business account", car_rental: "Car rental", admin_identity: "Online application" },
  de: { travel_booking: "Reisende", company_b2b: "Geschäftskonto", car_rental: "Mietwagen", admin_identity: "Online-Antrag" },
  es: { travel_booking: "Datos de los pasajeros", company_b2b: "Cuenta de empresa", car_rental: "Alquiler de coche", admin_identity: "Solicitud en línea" },
  it: { travel_booking: "Dati dei passeggeri", company_b2b: "Account aziendale", car_rental: "Noleggio auto", admin_identity: "Domanda online" },
  pt: { travel_booking: "Dados dos passageiros", company_b2b: "Conta empresarial", car_rental: "Aluguer de carro", admin_identity: "Pedido online" },
  nl: { travel_booking: "Gegevens van de reizigers", company_b2b: "Zakelijk account", car_rental: "Autohuur", admin_identity: "Online aanvraag" },
};
export const formsHeading = (lang: Lang, flow: keyof (typeof HEADINGS)["fr"]) => pick(HEADINGS, lang)[flow];

/** Canonical civility (lab's own table, spec section 7): mr, mrs, ms, miss, mx, dr. */
export type Civility = "mr" | "mrs" | "ms" | "miss" | "mx" | "dr";
/** Civility options a page of each language lists, with their canonical value; the first two always, the others drawn. */
export const CIVILITY_OPTIONS: Record<FormsLang, [string, Civility][]> = {
  fr: [["M.", "mr"], ["Mme", "mrs"], ["Mlle", "miss"], ["Dr", "dr"]],
  en: [["Mr", "mr"], ["Ms", "ms"], ["Mrs", "mrs"], ["Miss", "miss"], ["Mx", "mx"], ["Dr", "dr"]],
  de: [["Herr", "mr"], ["Frau", "mrs"], ["Dr.", "dr"]],
  es: [["Sr.", "mr"], ["Sra.", "mrs"], ["Srta.", "miss"], ["Dr.", "dr"]],
  it: [["Sig.", "mr"], ["Sig.ra", "mrs"], ["Sig.na", "miss"], ["Dott.", "dr"]],
  pt: [["Sr.", "mr"], ["Sra.", "mrs"], ["Menina", "miss"], ["Dr.", "dr"]],
  nl: [["Dhr.", "mr"], ["Mevr.", "mrs"], ["Mej.", "miss"], ["Dr.", "dr"]],
};
/** Canonical civility of a vault honorific (the lab writes them: forms-data.ts HONORIFIC). */
export const CIVILITY_OF: Readonly<Record<string, Civility>> = {
  "M.": "mr", Mme: "mrs", Mr: "mr", Ms: "ms", Herr: "mr", Frau: "mrs", "Sr.": "mr", "Sra.": "mrs", "Sig.": "mr", "Sig.ra": "mrs",
  "Dhr.": "mr", "Mevr.": "mrs",
};

export type SexCode = "f" | "m" | "x";
/** Sex options per language with their canonical code; the third (other) is drawn. */
export const SEX_OPTIONS: Record<FormsLang, [string, SexCode][]> = {
  fr: [["Homme", "m"], ["Femme", "f"], ["Autre", "x"]],
  en: [["Male", "m"], ["Female", "f"], ["Other", "x"]],
  de: [["Männlich", "m"], ["Weiblich", "f"], ["Divers", "x"]],
  es: [["Hombre", "m"], ["Mujer", "f"], ["Otro", "x"]],
  it: [["Maschio", "m"], ["Femmina", "f"], ["Altro", "x"]],
  pt: [["Masculino", "m"], ["Feminino", "f"], ["Outro", "x"]],
  nl: [["Man", "m"], ["Vrouw", "f"], ["Anders", "x"]],
};

/** Countries the nationality and issuing country lists show. */
export const LIST_COUNTRIES = ["FR", "DE", "ES", "IT", "PT", "NL", "BE", "CH", "GB", "US", "CA", "MA"] as const;
/** Demonyms (masculine, feminine) of the list countries per language: the lab's own table. */
export const DEMONYMS: Record<FormsLang, Record<(typeof LIST_COUNTRIES)[number], [string, string]>> = {
  fr: { FR: ["Français", "Française"], DE: ["Allemand", "Allemande"], ES: ["Espagnol", "Espagnole"], IT: ["Italien", "Italienne"],
    PT: ["Portugais", "Portugaise"], NL: ["Néerlandais", "Néerlandaise"], BE: ["Belge", "Belge"], CH: ["Suisse", "Suisse"],
    GB: ["Britannique", "Britannique"], US: ["Américain", "Américaine"], CA: ["Canadien", "Canadienne"], MA: ["Marocain", "Marocaine"] },
  en: { FR: ["French", "French"], DE: ["German", "German"], ES: ["Spanish", "Spanish"], IT: ["Italian", "Italian"],
    PT: ["Portuguese", "Portuguese"], NL: ["Dutch", "Dutch"], BE: ["Belgian", "Belgian"], CH: ["Swiss", "Swiss"],
    GB: ["British", "British"], US: ["American", "American"], CA: ["Canadian", "Canadian"], MA: ["Moroccan", "Moroccan"] },
  de: { FR: ["Französisch", "Französisch"], DE: ["Deutsch", "Deutsch"], ES: ["Spanisch", "Spanisch"], IT: ["Italienisch", "Italienisch"],
    PT: ["Portugiesisch", "Portugiesisch"], NL: ["Niederländisch", "Niederländisch"], BE: ["Belgisch", "Belgisch"], CH: ["Schweizerisch", "Schweizerisch"],
    GB: ["Britisch", "Britisch"], US: ["Amerikanisch", "Amerikanisch"], CA: ["Kanadisch", "Kanadisch"], MA: ["Marokkanisch", "Marokkanisch"] },
  es: { FR: ["Francés", "Francesa"], DE: ["Alemán", "Alemana"], ES: ["Español", "Española"], IT: ["Italiano", "Italiana"],
    PT: ["Portugués", "Portuguesa"], NL: ["Neerlandés", "Neerlandesa"], BE: ["Belga", "Belga"], CH: ["Suizo", "Suiza"],
    GB: ["Británico", "Británica"], US: ["Estadounidense", "Estadounidense"], CA: ["Canadiense", "Canadiense"], MA: ["Marroquí", "Marroquí"] },
  it: { FR: ["Francese", "Francese"], DE: ["Tedesco", "Tedesca"], ES: ["Spagnolo", "Spagnola"], IT: ["Italiano", "Italiana"],
    PT: ["Portoghese", "Portoghese"], NL: ["Olandese", "Olandese"], BE: ["Belga", "Belga"], CH: ["Svizzero", "Svizzera"],
    GB: ["Britannico", "Britannica"], US: ["Statunitense", "Statunitense"], CA: ["Canadese", "Canadese"], MA: ["Marocchino", "Marocchina"] },
  pt: { FR: ["Francês", "Francesa"], DE: ["Alemão", "Alemã"], ES: ["Espanhol", "Espanhola"], IT: ["Italiano", "Italiana"],
    PT: ["Português", "Portuguesa"], NL: ["Neerlandês", "Neerlandesa"], BE: ["Belga", "Belga"], CH: ["Suíço", "Suíça"],
    GB: ["Britânico", "Britânica"], US: ["Americano", "Americana"], CA: ["Canadiano", "Canadiana"], MA: ["Marroquino", "Marroquina"] },
  nl: { FR: ["Frans", "Franse"], DE: ["Duits", "Duitse"], ES: ["Spaans", "Spaanse"], IT: ["Italiaans", "Italiaanse"],
    PT: ["Portugees", "Portugese"], NL: ["Nederlands", "Nederlandse"], BE: ["Belgisch", "Belgische"], CH: ["Zwitsers", "Zwitserse"],
    GB: ["Brits", "Britse"], US: ["Amerikaans", "Amerikaanse"], CA: ["Canadees", "Canadese"], MA: ["Marokkaans", "Marokkaanse"] },
};

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

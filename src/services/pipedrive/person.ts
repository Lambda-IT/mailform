// @ts-ignore
import {NewPerson} from "pipedrive";
import {ContactForm} from "../../@types/target";
import {v4 as uuidv4} from "uuid";
import {getCurrentUTCDateTime, Response} from "../pipedrive";
import {LANGUAGE_MAPPER} from "./language-mapper";
import {
    LanguageKey,
    LanguageOption,
    PersonLangFieldResponse,
    Field,
    LabelField,
    PersonLabelFieldResponse,
} from "./types";

interface PersonOptions {
    name: string;
    owner_id: number;
    email: {value: string}[];
    add_time: string;
    phone?: {value: string}[]; // phone is optional
}

export const LANGUAGE_FILED_ID = 9099;
export const LANGUAGE_KEY = "bab84189617691c8d2549a1331ad7d8ceca26653";
export const LANGUAGE_MAP: {[key: string]: number} = {
    Deutsch: 88,
    Englisch: 89,
    Französisch: 90,
    Spanisch: 91,
    Italienisch: 92,
};

const LABEL_FIELD_ID = "9105";
const LABEL_OPTION = {
    id: 114,
    label: "Inbound Webformular",
};

export class PipedrivePersonService {
    // https://github.com/pipedrive/client-nodejs/blob/master/docs/PersonsApi.md#addPerson
    async addSimplePerson(client: any, req: ContactForm, owner_id: number): Promise<Response> {
        const origin_id = `fidentity_backend_${uuidv4()}`;
        console.info(
            `PipedrivePersonService -> addPerson -> send a addPerson request to Pipedrive, origin_id: ${origin_id}`
        );

        const opts: PersonOptions = {
            name: `${req.firstname} ${req.lastname}`,
            owner_id: owner_id,
            email: [
                {
                    value: req.email,
                },
            ],
            add_time: getCurrentUTCDateTime(),
        };

        if (req.phone) {
            opts.phone = [
                {
                    value: req.phone,
                },
            ];
        }
        console.debug(`PipedrivePersonService -> addPerson -> request opts: ${JSON.stringify(opts)}`);

        // Assuming NewPerson.constructFromObject is a method that takes the opts object
        const newPerson = NewPerson.constructFromObject(opts);

        const response = await client.addPerson(newPerson);
        console.info(`PipedrivePersonService -> addPerson -> received response: ${JSON.stringify(response)}`);

        return response.success === true
            ? {
                  success: true,
                  data: response.data,
                  msg: "Everything is okay",
              }
            : {
                  success: false,
                  error: new Error(response.data),
                  msg: "Request goes wrong -> add person",
              };
    }

    async addLanguageForPerson(client: any, req: ContactForm, person_id: number): Promise<Response> {
        const language = req.language;

        if (!language) {
            return {
                success: false,
                error: new Error("The language was not passed you cannot set the language"),
            };
        }
        if (!LANGUAGE_MAPPER.hasOwnProperty(language as LanguageKey)) {
            return {
                success: false,
                error: new Error(`We do not support this language: ${language}`),
            };
        }

        const langCode = LANGUAGE_MAP[LANGUAGE_MAPPER[language as LanguageKey].germanName];
        const updateData = {
            [LANGUAGE_KEY]: langCode,
        };

        try {
            const response = await client.updatePerson(person_id, updateData);
            if (response.success) {
                return {
                    success: true,
                    data: response.data,
                    msg: `Person Update Success, person_id: ${person_id}, Everything is okay`,
                };
            } else {
                return {
                    success: false,
                    error: new Error(response.data),
                    msg: "Request goes wrong -> update person language",
                };
            }
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error : new Error(String(error)),
                msg: "An error occurred while updating the person",
            };
        }
    }

    async checkLanguage(client: any): Promise<PersonLangFieldResponse> {
        const failMsg = "Request goes wrong -> no response";
        const response = await client.getPersonField(LANGUAGE_FILED_ID);
        if (response.success) {
            console.info(`checkLanguage -> getPersonField response: ${JSON.stringify(response)}`);
            const langField = response.data as Field<LanguageOption>;
            const isValid = this.validateLanguageField(langField);
            return {
                success: isValid,
                data: langField,
                msg: isValid
                    ? "Language check PASS, Everything is okay"
                    : `Language check FAIL, because we can't find a different LANGUAGE_KEY or language options has chanced, data: ${JSON.stringify(langField)}`,
            };
        }

        return {
            success: false,
            error: new Error(response.data),
            msg: "Request goes wrong -> getPersonField for the Language goes wrong",
        };
    }

    async addInboundLabelToPerson(person_id: number) {
        
    }

    async checkLabelId(client: any): Promise<PersonLabelFieldResponse> {
        const response = await client.getPersonField(LABEL_FIELD_ID);

        if (response.success) {
            console.info(`checkLabelId -> getPersonField response: ${JSON.stringify(response)}`);
            const labelField = response.data as Field<LabelField>;
            const isValid = this.validateLabelIdField(labelField);
            return {
                success: isValid,
                data: labelField,
                msg: isValid
                    ? "Label check PASS, Everything is okay"
                    : `Label check FAIL, because we can't find: ${JSON.stringify(LABEL_OPTION)} in ${JSON.stringify(labelField)}`,
            };
        }

        return {
            success: false,
            error: new Error(response.data),
            msg: "Request goes wrong -> getPersonField for the label id goes wrong",
        };
    }

    validateLanguageField = (languageField: Field<LanguageOption>): boolean => {
        if (languageField.key !== LANGUAGE_KEY) return false;

        return Object.entries(LANGUAGE_MAP).every(([label, id]) =>
            languageField.options.some((option) => option.id === id && option.label === label)
        );
    };

    validateLabelIdField = (labelField: Field<LabelField>): boolean => {
        return Object.values(labelField.options).some(
            (item) => item.id === LABEL_OPTION.id && item.label === LABEL_OPTION.label
        );
    };

    getLang = (req: ContactForm): string | null => {
        return req.language && LANGUAGE_MAPPER.hasOwnProperty(req.language)
            ? LANGUAGE_MAPPER[req.language as LanguageKey].germanName
            : null;
    };
}

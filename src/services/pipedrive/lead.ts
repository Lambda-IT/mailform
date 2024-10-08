import {AddLeadRequest} from 'pipedrive';
import {ContactForm} from '../../@types/target';
import {PIPEDRIVE_INFO_ACC_ID} from '../pipedrive';
import logger from './logger';
import {LeadLabel, LeadLabels, Response} from './types';

interface LeadOptions {
    title: string;
    owner_id: number;
    person_id: number;
    organization_id?: number;
    label_ids?: string[];
}

const LEAD_LABEL_OPTION: LeadLabel = {
    id: '74b21c90-f326-11ed-98c5-c58df5a19268',
    name: 'Inbound Webformular',
};

export class PipedriveLeadService {
    // https://github.com/pipedrive/client-nodejs/blob/master/docs/LeadsApi.md#addLead
    async addLead(
        leadClient: any,
        leadLabelClient: any,
        req: ContactForm,
        personId: number,
        organizationId?: number
    ): Promise<Response> {
        const opt: LeadOptions = {
            title: `Anfrage Webformular ${req.name}`,
            owner_id: PIPEDRIVE_INFO_ACC_ID,
            person_id: personId,
        };

        if (organizationId) {
            opt.organization_id = organizationId;
        }

        try {
            const leadLabelResp = await leadLabelClient.getLeadLabels();
            if (leadLabelResp.success && this.validateLeadLabel(leadLabelResp, LEAD_LABEL_OPTION)) {
                opt.label_ids = [LEAD_LABEL_OPTION.id];
            } else
                throw new Error(`getLeadLabels request failed or validation failed, leadLabelResp: ${leadLabelResp}`);
        } catch (error) {
            logger.error(`[Error] with getLeadLabels`, {error});
        }

        const opts = AddLeadRequest.constructFromObject(opt);

        try {
            const response = await leadClient.addLead(opts);
            if (response.success === true) {
                return {
                    success: true,
                    data: response.data,
                    log: () => logger.info('Successfully created a lead, Everything is okay'),
                };
            } else {
                return {
                    success: false,
                    error: new Error(JSON.stringify(response.data)),
                    log: () => logger.error('Request goes wrong -> add Lead'),
                };
            }
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : JSON.stringify(error);
            return {
                success: false,
                error: error instanceof Error ? error : new Error(errorMessage),
                log: () => logger.error('An error occurred while adding the lead', {error}),
            };
        }
    }

    private validateLeadLabel = (labels: LeadLabels, shouldBe: LeadLabel): boolean => {
        return Object.values(labels.data).some(
            (item) => item.id === shouldBe.id && item.name.trim().toLowerCase() === shouldBe.name.trim().toLowerCase()
        );
    };
}


import { useDate, Resource } from '@tomic/react';
import { ontology } from '../../ontologies/ontology';

export enum Status {
    Draft = 1,
    Current,
    Stale,
    Retired
}

export class StatusInfo {
    status: Status;
    approvedOn?: Date;
    updatedOn?: Date;
    staleOn?: Date;
    retiredOn?: Date;

    constructor(approvedOn?: Date, updatedOn?: Date, staleOn?: Date, retiredOn?: Date) {
        this.approvedOn = approvedOn;
        this.updatedOn = updatedOn;
        this.staleOn = staleOn;
        this.retiredOn = retiredOn;

        if (retiredOn) {
            this.status = Status.Retired;
        }
        else if (staleOn) {
            this.status = Status.Stale;
        }
        else if (approvedOn) {
            this.status = Status.Current;
        }
        else {
            this.status = Status.Draft;
        }
    }

    get isDraft(): boolean {
        return this.status == Status.Draft;
    }

    get isCurrent(): boolean {
        return this.status == Status.Current;
    }

    get isStale(): boolean {
        return this.status == Status.Stale;
    }

    get isRetired(): boolean {
        return this.status == Status.Retired;
    }
}

export function useStatusInfo(resource: Resource): StatusInfo {
    return new StatusInfo(
        useDate(resource, ontology.properties.approvedon),
        useDate(resource, ontology.properties.updatedon),
        useDate(resource, ontology.properties.staleon),
        useDate(resource, ontology.properties.retiredon)
    );
}
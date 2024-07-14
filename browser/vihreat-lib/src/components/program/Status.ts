
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
    now: Date;
    approvedOn?: Date;
    updatedOn?: Date;
    staleOn?: Date;
    retiredOn?: Date;

    constructor(now: Date, approvedOn?: Date, updatedOn?: Date, staleOn?: Date, retiredOn?: Date) {
        this.now = now;
        this.approvedOn = approvedOn;
        this.updatedOn = updatedOn;
        this.staleOn = staleOn;
        this.retiredOn = retiredOn;

        if (retiredOn && (retiredOn <= now)) {
            this.status = Status.Retired;
        }
        else if (staleOn && (staleOn <= now)) {
            this.status = Status.Stale;
        }
        else if (approvedOn && (approvedOn <= now)) {
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

    get statusString(): string {
        switch (this.status) {
            case Status.Draft:
                return "draft";
            case Status.Current:
                return "current";
            case Status.Stale:
                return "stale";
            case Status.Retired:
                return "retired";
            default:
                return "";
        }
    }
}

export function useStatusInfo(resource: Resource): StatusInfo {
    return new StatusInfo(
        new Date(),
        useDate(resource, ontology.properties.approvedon),
        useDate(resource, ontology.properties.updatedon),
        useDate(resource, ontology.properties.staleon),
        useDate(resource, ontology.properties.retiredon)
    );
}
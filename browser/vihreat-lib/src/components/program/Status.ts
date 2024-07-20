
import { useDate, Resource } from '@tomic/react';
import { ontology } from '../../ontologies/ontology';

// "Traffic light" color
export enum StatusColor {
    Gray = 1,
    Green,
    Yellow,
    Red
}

interface StatusInfoProps {
    approvedOn?: Date;
    updatedOn?: Date;
    retiredOn?: Date;
    staleOn?: Date;
}

export class StatusInfo {
    color: StatusColor;
    now: Date;
    approvedOn?: Date;
    updatedOn?: Date;
    retiredOn?: Date;
    staleOn?: Date;

    constructor(now: Date, { approvedOn, updatedOn, retiredOn, staleOn }: StatusInfoProps) {
        this.now = now;
        this.approvedOn = approvedOn;
        this.updatedOn = updatedOn;
        this.retiredOn = retiredOn;
        this.staleOn = staleOn;

        if (!this.hasBeenApproved) {
            this.color = StatusColor.Gray;
        }
        else {
            if (this.hasBeenRetired) {
                this.color = StatusColor.Red;
            }
            else if (this.hasGoneStale) {
                this.color = StatusColor.Yellow;
            }
            else {
                this.color = StatusColor.Green;
            }
        }
    }

    get hasBeenApproved(): boolean {
        return Boolean(this.approvedOn && this.approvedOn <= this.now);
    }

    get hasBeenUpdated(): boolean {
        return Boolean(this.updatedOn && this.updatedOn <= this.now);
    }

    get hasGoneStale(): boolean {
        return Boolean(this.staleOn && this.staleOn <= this.now);
    }

    get hasBeenRetired(): boolean {
        return Boolean(this.retiredOn && this.retiredOn <= this.now);
    }

    get isGray(): boolean {
        return this.color == StatusColor.Gray;
    }

    get isGreen(): boolean {
        return this.color == StatusColor.Green;
    }

    get isYellow(): boolean {
        return this.color == StatusColor.Yellow;
    }

    get isRed(): boolean {
        return this.color == StatusColor.Red;
    }
}

export function useStatusInfo(resource: Resource): StatusInfo {
    return new StatusInfo(
        new Date(),
        {
            approvedOn: useDate(resource, ontology.properties.approvedon),
            updatedOn: useDate(resource, ontology.properties.updatedon),
            staleOn: useDate(resource, ontology.properties.staleon),
            retiredOn: useDate(resource, ontology.properties.retiredon)
        }
    );
}
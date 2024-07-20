import { StatusInfo } from './Status';

interface WithStatusProps {
  status: StatusInfo;
}

export function FrontMatter({ status }: WithStatusProps): JSX.Element {
  return (
    <div className='vo-program-frontmatter'>
      <Banner status={status} />
      <ApprovedLine status={status} />
      <UpdatedLine status={status} />
      <RetiredLine status={status} />
    </div>
  );
}

function Banner({ status }: WithStatusProps): JSX.Element {
  if (status.isGreen) {
    return <></>;
  }
  else if (status.isGray) {
    return (
      <p className='vo-program-status-banner vo-program-status-banner-draft'>
        ⚠ Tämä on ohjelmaluonnos. Se ei ole eikä ole koskaan ollut voimassa.
      </p>
    );
  }
  else if (status.isYellow) {
    return (
      <p className='vo-program-status-banner vo-program-status-banner-stale'>
        ⚠ Tämä ohjelma voi sisältää vanhentunutta asiasisältöä.
      </p>
    );
  }
  else if (status.isRed) {
    return (
      <p className='vo-program-status-banner vo-program-status-banner-retired'>
        ⚠ Tämä ohjelma ei ole enää voimassa.
      </p>
    );
  }
  else {
    return (
      <p className='vo-program-status-banner vo-program-status-banner-retired'>
        ⚠ Tämän ohjelman voimassaolotietoja ei voitu selvittää.
      </p>
    );
  }
}

function ApprovedLine({ status }: WithStatusProps): JSX.Element {
  if (status.hasBeenApproved) {
    return (
      <p className='vo-program-status-info'>
        Hyväksyttiin {dateToString(status.approvedOn)}
      </p>
    );
  }
  else {
    return <></>;
  }
}

function UpdatedLine({ status }: WithStatusProps): JSX.Element {
  if (status.hasBeenUpdated) {
    return (
      <p className='vo-program-status-info'>
        Päivitetty viimeksi {dateToString(status.updatedOn)}
      </p>
    );
  }
  else {
    return <></>;
  }
}

function RetiredLine({ status }: WithStatusProps): JSX.Element {
  if (status.hasBeenRetired) {
    return (
      <p className='vo-program-status-info'>
        Voimassaolo päättyi {dateToString(status.retiredOn)}
      </p>
    );
  }
  else if (status.retiredOn) {
    return (
      <p className='vo-program-status-info'>
        Voimassaolo päättyy {dateToString(status.retiredOn)}
      </p>
    );
  }
  else {
    return <></>;
  }
}

function dateToString(date?: Date): string {
  if (date) {
    return date.toLocaleString('fi-FI', {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
    });
  }
  else {
    return '??.??.????';
  }
}
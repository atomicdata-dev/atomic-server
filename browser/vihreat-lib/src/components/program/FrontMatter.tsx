interface FrontMatterProps {
  approvedOn?: Date;
}

export function FrontMatter({ approvedOn }: FrontMatterProps): JSX.Element {
  if (approvedOn) {
    const approvedOnStr = approvedOn.toLocaleString('fi-FI', {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
    });

    return (
      <div className='vo-program-frontmatter'>
        <p>Hyväksytty {approvedOnStr}</p>
      </div>
    );
  } else {
    return <></>;
  }
}
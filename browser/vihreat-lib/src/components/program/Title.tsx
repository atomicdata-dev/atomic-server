interface TitleProps {
  title: string;
  subtitle?: string;
}

export function Title({ title, subtitle }: TitleProps): JSX.Element {
  if (subtitle) {
    return (
      <div className="vo-program-titlematter">
        <h1 className="vo-program-title">{title}</h1>
        <h1 className="vo-program-subtitle">{subtitle}</h1>
      </div>
    );
  } else {
    return (
      <div className="vo-program-titlematter">
        <h1 className="vo-program-title">{title}</h1>
      </div>
    );

  }
}
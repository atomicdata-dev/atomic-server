interface TitleProps {
  title: string;
}

export function Title({ title }: TitleProps): JSX.Element {
  return (
    <h1 className="vo-program-title">{title}</h1>
  );
}
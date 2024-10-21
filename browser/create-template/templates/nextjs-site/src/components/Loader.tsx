const Loader = ({
  resource,
  children,
}: {
  resource: { loading: boolean; title: string };
  children: React.ReactNode;
}) => {
  if (resource.loading) {
    return <div>Loading...</div>;
  }

  return children;
};

export default Loader;

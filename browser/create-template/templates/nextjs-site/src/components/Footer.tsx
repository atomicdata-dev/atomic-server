import Container from "./Layout/Container";
import styles from "./Footer.module.css";

const Footer = () => {
  const year = new Date().getFullYear();
  return (
    <footer className={styles.footer}>
      <Container>
        <p>&copy; {year} Your Company</p>
      </Container>
    </footer>
  );
};

export default Footer;

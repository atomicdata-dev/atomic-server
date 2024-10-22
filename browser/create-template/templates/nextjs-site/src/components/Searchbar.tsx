'use client';

import HStack from './Layout/HStack';
import styles from './Searchbar.module.css';
import FaMagnifyingGlass from './Icons/magnifying-glass-solid.svg';
import Image from 'next/image';

const Searchbar = ({
  value,
  handler,
  placeholder = 'Search...',
}: {
  value: string;
  handler: (event: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
}) => {
  return (
    <div className={styles.searchBar}>
      <HStack align='center' gap='1ch'>
        <Image
          priority
          width={16}
          height={16}
          src={FaMagnifyingGlass}
          alt='search'
        />
        <input
          className={styles.input}
          type='search'
          value={value}
          onChange={handler}
          placeholder={placeholder}
        />
      </HStack>
    </div>
  );
};

export default Searchbar;

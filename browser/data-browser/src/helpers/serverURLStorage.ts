const ServerURLStorageKEY = 'serverUrl';

export const serverURLStorage = {
  set(url: string) {
    localStorage.setItem(ServerURLStorageKEY, JSON.stringify(url));
  },
  get() {
    try {
      const val = localStorage.getItem(ServerURLStorageKEY);

      return JSON.parse(val as string);
    } catch (e) {
      return undefined;
    }
  },
};

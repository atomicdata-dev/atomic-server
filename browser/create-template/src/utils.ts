import readline from 'node:readline';

export function ask(question: string): Promise<string> {
  return new Promise(resolve => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(question, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

export function log(message: unknown, ...optionalParams: unknown[]): void {
  // eslint-disable-next-line no-console
  console.log(message, ...(optionalParams ?? []));
}

# Examples

## Realtime Todo app

In this example, we create a basic to-do app that persists on the server and updates in real-time when anyone makes changes.
If you were to make this in vanilla react without any kind of persistence it would probably look almost the same.
The main difference is the use of the `useArray` and `useBoolean` hooks instead of `useState`.

```jsx
import { useArray, useBoolean, useResource } from '@tomic/react';
import { useState } from 'react';

 export const TodoList = () => {
  const store = useStore();
  const checklist = useResource<Checklist>('https://my-server/checklist/1');

  const [todos, setTodos] = useArray(checklist, todoApp.properties.todos, {
    commit: true,
  });

  const [inputValue, setInputValue] = useState('');

  const removeTodo = (subject: string) => {
    setTodos(todos.filter(todo => todo !== subject));
  };

  const addTodo = async () => {
    const newTodo = await store.newResource({
      isA: todoApp.classes.todoItem,
      parent: checklist.subject,
      propVals: {
        [core.properties.name]: inputValue,
        [todoApp.properties.done]: false,
      },
    });

    await newTodo.save();

    setTodos([...todos, newTodo.subject]);
    setInputValue('');
  };

  return (
    <div>
      <ul>
        {todos.map(subject => (
          <li key={subject}>
            <Todo subject={subject} onDelete={removeTodo} />
          </li>
        ))}
      </ul>
      <input
        type='text'
        placeholder='Add a new todo...'
        value={inputValue}
        onChange={e => setInputValue(e.target.value)}
      />
      <button onClick={addTodo}>Add</button>
    </div>
  );
};

interface TodoProps {
  subject: string;
  onDelete: (subject: string) => void;
}

const Todo = ({ subject, onDelete }: TodoProps) => {
  const resource = useResource<Todo>(subject);
  const [done, setDone] = useBoolean(resource, todoApp.properties.done, {
    commit: true,
  });

  const deleteTodo = () => {
    resource.destroy();
    onDelete(subject);
  };

  return (
    <span>
      <input
        type='checkbox'
        checked={done}
        onChange={e => setDone(e.target.checked)}
      />
      {resource.title}
      <button onClick={deleteTodo}>Delete</button>
    </span>
  );
};
```


# useValue

The `useValue` hook is used to read and write values from a resource.
It looks and functions a lot like React's useState hook.

```jsx
  import { useValue } from '@tomic/react';

  const MyComponent = ({ subject }) => {
    const resource = useResource(subject);
    const [value, setValue] = useValue(resource, 'https://example.com/property');

    return (
      <div>
        <input value={value} onChange={e => setValue(e.target.value)} />
      </div>
    );
  };
```

The `useValue` hook does not save the resource by default when the value is changed.
This can be configured by passing an options object as the third argument with `commit` set to true.

In practice, you will use typed versions of `useValue` more often.
These offer better typescript typing and validation on writes.

The following value hooks are available:

- `useString` for string, slug and markdown values.
- `useNumber` for float and integer values.
- `useBoolean` for boolean values.
- `useDate` for date and timestamp values.
- `useArray` for ResourceArray values.

## Reference

### Parameters

- **resource**: `Resource` - The resource object to read and write from.
- **property**: `string` - The subject of the property you want to read and write.
- **options**: `object` - (Optional) Options for how the value should be read and written.

**Options**:
| Name | Type | Description |
| --- | --- | --- |
| commit | `boolean` | If true, the resource will be saved when the value is changed. Default: `false` |
| validate | `boolean` | If true, the value will be validated against the properties datatype. Default: `true`|
| commitDebounce | `number` | The number of milliseconds to wait before saving the resource. Default: `100`|
| handleValidationError | `function` | A function that is called when the value is invalid. |

### Returns

Returns an array (tuple) with two items:
- **value**: type depends on the hook used - The value of the property.
- **setValue**: `function` - A function to set the value of the property.

## Some Examples

### Realtime Todo app

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

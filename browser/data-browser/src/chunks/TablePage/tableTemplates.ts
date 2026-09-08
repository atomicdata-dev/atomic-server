import { taskSchema, timeTrackingSchema } from '@tomic/lib';
import type { IconType } from 'react-icons';
import {
  FaBook,
  FaBookmark,
  FaBoxesStacked,
  FaBriefcase,
  FaBug,
  FaCartShopping,
  FaDumbbell,
  FaHandshake,
  FaListCheck,
  FaReceipt,
  FaSeedling,
  FaStopwatch,
  FaTableCellsLarge,
  FaUserGroup,
} from 'react-icons/fa6';
import { TableSpec } from './createTableFromSpec';

export interface TableTemplate {
  id: string;
  title: string;
  description: string;
  /** What a single row of this table is called — becomes the row class's name. */
  rowName: string;
  /** Shown on the template's card in the New Table dialog. */
  icon: IconType;
  /** The table to build. Absent for the `blank` starting point. */
  spec?: Omit<TableSpec, 'name' | 'rowName'>;
}

/**
 * Starting points offered in the New Table dialog (and to the assistant, through
 * `list_table_templates`). `blank` is the default.
 *
 * Every one of these is *data and configuration only* — columns, views, computed
 * columns, totals — and none of them ships a renderer. That is the whole point of
 * `planning/table-templates-and-mini-apps.md`: a mini-app should be a template,
 * not a view kind. Adding one here is the cheapest rung on that ladder, and the
 * same config a person (or the assistant) can build by hand afterwards.
 *
 * `tableTemplates.test.ts` checks each spec against the capabilities that
 * actually exist — a column referenced by a total, a sort or a computed column's
 * argument must be a real column of the right datatype.
 */
export const TABLE_TEMPLATES: TableTemplate[] = [
  {
    id: 'blank',
    title: 'Blank',
    description: 'An empty table you configure yourself.',
    rowName: 'Row',
    icon: FaTableCellsLarge,
  },
  {
    id: 'issue-tracker',
    title: 'Issue Tracker',
    description: 'Status, Assignee and Priority, plus a kanban board.',
    rowName: 'Issue',
    icon: FaBug,
    spec: {
      columns: [
        {
          name: 'Description',
          type: 'markdown',
          propertySubject: taskSchema.properties.body,
        },
        {
          name: 'Status',
          propertySubject: taskSchema.properties.status,
          type: 'select',
          options: ['Todo', 'Doing', 'Blocked', 'Done'],
        },
        {
          name: 'Assignee',
          type: 'text',
          propertySubject: taskSchema.properties.assignee,
        },
        {
          name: 'Priority',
          type: 'select',
          options: ['Low', 'Medium', 'High'],
        },
      ],
      views: [
        {
          name: 'Board',
          kind: 'kanban',
          groupByColumn: 'Status',
          default: true,
        },
        { name: 'All issues', kind: 'table' },
      ],
    },
  },
  {
    id: 'project-tasks',
    title: 'Project tasks',
    description: 'A board, a calendar, and the estimated hours added up.',
    rowName: 'Task',
    icon: FaListCheck,
    spec: {
      columns: [
        {
          name: 'Status',
          propertySubject: taskSchema.properties.status,
          type: 'select',
          options: ['Todo', 'Doing', 'Blocked', 'Done'],
        },
        {
          name: 'Due date',
          type: 'date',
          propertySubject: taskSchema.properties.dueDate,
        },
        {
          name: 'Assignee',
          type: 'text',
          propertySubject: taskSchema.properties.assignee,
        },
        { name: 'Estimate', type: 'decimal', description: 'In hours' },
        {
          name: 'Description',
          type: 'markdown',
          propertySubject: taskSchema.properties.body,
        },
      ],
      views: [
        {
          name: 'Board',
          kind: 'kanban',
          groupByColumn: 'Status',
          default: true,
        },
        { name: 'Schedule', kind: 'calendar', groupByColumn: 'Due date' },
        {
          name: 'All tasks',
          kind: 'table',
          sortByColumn: 'Due date',
          sortDesc: false,
          aggregates: [{ function: 'sum', column: 'Estimate' }],
          breakdownColumn: 'Status',
          breakdownGranularity: 'exact',
        },
      ],
    },
  },
  {
    id: 'time-tracker',
    title: 'Time tracker',
    description: 'A start/stop timer, grouped by project.',
    rowName: 'Time entry',
    icon: FaStopwatch,
    spec: {
      schema: timeTrackingSchema(),
      columns: [
        { name: 'Start', type: 'datetime', schemaProperty: 'work-start' },
        { name: 'End', type: 'datetime', schemaProperty: 'work-end' },
        {
          name: 'Project',
          type: 'relation',
          schemaProperty: 'work-project',
        },
        { name: 'Person', type: 'relation', schemaProperty: 'work-person' },
        { name: 'Billable', type: 'checkbox', schemaProperty: 'work-billable' },
      ],
      views: [
        {
          name: 'Timer',
          kind: 'timer',
          // The timer needs both halves of the interval: `groupByColumn` is its
          // start, `endColumn` its end.
          groupByColumn: 'Start',
          endColumn: 'End',
          // Duration is not a timer feature but a derived column: `elapsed`
          // ticks from Start until End is stamped. Configuration, so the same
          // column is available to any other view or template.
          derivedColumns: [
            {
              name: 'Duration',
              kind: 'elapsed',
              args: { from: 'Start', until: 'End' },
            },
          ],
          default: true,
        },
        { name: 'All entries', kind: 'table' },
      ],
    },
  },
  {
    id: 'expenses',
    title: 'Expenses',
    description: 'Receipts attached, summed and broken down per month.',
    rowName: 'Expense',
    icon: FaReceipt,
    spec: {
      columns: [
        { name: 'Amount', type: 'decimal' },
        { name: 'Date', type: 'date' },
        {
          name: 'Category',
          type: 'select',
          options: [
            'Food',
            'Transport',
            'Housing',
            'Software',
            'Travel',
            'Other',
          ],
        },
        { name: 'Receipt', type: 'file' },
        { name: 'Notes', type: 'text' },
      ],
      views: [
        {
          name: 'All expenses',
          kind: 'table',
          sortByColumn: 'Date',
          sortDesc: true,
          aggregates: [{ function: 'sum', column: 'Amount' }],
          breakdownColumn: 'Date',
          breakdownGranularity: 'month',
          columnOrder: ['Name', 'Date', 'Category', 'Amount', 'Receipt'],
          default: true,
        },
        {
          name: 'By category',
          kind: 'table',
          aggregates: [
            { function: 'sum', column: 'Amount' },
            { function: 'avg', column: 'Amount', row: 1 },
          ],
          breakdownColumn: 'Category',
          breakdownGranularity: 'exact',
        },
      ],
    },
  },
  {
    id: 'crm',
    title: 'Deals (CRM)',
    description: 'A pipeline board, its value, and days since contact.',
    rowName: 'Deal',
    icon: FaHandshake,
    spec: {
      columns: [
        { name: 'Company', type: 'text' },
        {
          name: 'Stage',
          type: 'select',
          options: ['Lead', 'Contacted', 'Proposal', 'Won', 'Lost'],
        },
        { name: 'Value', type: 'decimal' },
        { name: 'Last contact', type: 'date' },
        { name: 'Owner', type: 'text' },
        { name: 'Notes', type: 'markdown' },
      ],
      views: [
        {
          name: 'Pipeline',
          kind: 'kanban',
          groupByColumn: 'Stage',
          default: true,
        },
        {
          name: 'All deals',
          kind: 'table',
          // Oldest contact first: the point of the view is who to chase.
          sortByColumn: 'Last contact',
          sortDesc: false,
          derivedColumns: [
            {
              name: 'Days since contact',
              kind: 'daysSince',
              args: { from: 'Last contact' },
            },
          ],
          aggregates: [{ function: 'sum', column: 'Value' }],
          breakdownColumn: 'Stage',
          breakdownGranularity: 'exact',
          columnOrder: [
            'Name',
            'Company',
            'Stage',
            'Value',
            'Last contact',
            'Days since contact',
            'Owner',
          ],
        },
      ],
    },
  },
  {
    id: 'job-applications',
    title: 'Job applications',
    description: 'Where each one stands, and how long it has waited.',
    rowName: 'Application',
    icon: FaBriefcase,
    spec: {
      columns: [
        { name: 'Company', type: 'text' },
        { name: 'Role', type: 'text' },
        {
          name: 'Stage',
          type: 'select',
          options: [
            'Wishlist',
            'Applied',
            'Interview',
            'Offer',
            'Rejected',
            'Withdrawn',
          ],
        },
        { name: 'Applied on', type: 'date' },
        { name: 'Link', type: 'text' },
        { name: 'Notes', type: 'markdown' },
      ],
      views: [
        {
          name: 'Pipeline',
          kind: 'kanban',
          groupByColumn: 'Stage',
          default: true,
        },
        {
          name: 'All applications',
          kind: 'table',
          sortByColumn: 'Applied on',
          sortDesc: true,
          derivedColumns: [
            {
              name: 'Waiting',
              kind: 'daysSince',
              args: { from: 'Applied on' },
            },
          ],
          breakdownColumn: 'Stage',
          breakdownGranularity: 'exact',
          columnOrder: [
            'Name',
            'Company',
            'Role',
            'Stage',
            'Applied on',
            'Waiting',
            'Link',
          ],
        },
      ],
    },
  },
  {
    id: 'reading-list',
    title: 'Reading list',
    description: 'Books by shelf, with your rating averaged.',
    rowName: 'Book',
    icon: FaBook,
    spec: {
      columns: [
        { name: 'Author', type: 'text' },
        {
          name: 'Status',
          type: 'select',
          options: ['Want to read', 'Reading', 'Finished', 'Abandoned'],
        },
        { name: 'Rating', type: 'number', description: 'Out of five' },
        { name: 'Finished on', type: 'date' },
        { name: 'Notes', type: 'markdown' },
      ],
      views: [
        {
          name: 'Shelves',
          kind: 'kanban',
          groupByColumn: 'Status',
          default: true,
        },
        {
          name: 'All books',
          kind: 'table',
          sortByColumn: 'Finished on',
          sortDesc: true,
          aggregates: [{ function: 'avg', column: 'Rating' }],
          breakdownColumn: 'Status',
          breakdownGranularity: 'exact',
        },
      ],
    },
  },
  {
    id: 'grocery-list',
    title: 'Grocery list',
    description: 'Grouped by aisle, with the basket priced up.',
    rowName: 'Item',
    icon: FaCartShopping,
    spec: {
      columns: [
        { name: 'Quantity', type: 'number' },
        {
          name: 'Aisle',
          type: 'select',
          options: [
            'Produce',
            'Bakery',
            'Dairy',
            'Meat & fish',
            'Frozen',
            'Pantry',
            'Drinks',
            'Household',
          ],
        },
        { name: 'Price', type: 'decimal', description: 'Per item' },
        { name: 'Bought', type: 'checkbox' },
      ],
      views: [
        {
          name: 'By aisle',
          kind: 'kanban',
          groupByColumn: 'Aisle',
          default: true,
        },
        {
          name: 'List',
          kind: 'table',
          derivedColumns: [
            {
              name: 'Line total',
              kind: 'product',
              args: { a: 'Quantity', b: 'Price' },
            },
          ],
          aggregates: [{ function: 'sum', column: 'Quantity' }],
          breakdownColumn: 'Aisle',
          breakdownGranularity: 'exact',
          columnOrder: [
            'Name',
            'Quantity',
            'Price',
            'Line total',
            'Aisle',
            'Bought',
          ],
          rowActions: [{ label: 'Got it', kind: 'toggle', column: 'Bought' }],
          // The bar you actually use a shopping list through.
          quickAdd: {
            label: 'Add item',
            field: 'Name',
            placeholder: 'What do you need?',
          },
        },
      ],
    },
  },
  {
    id: 'workout-log',
    title: 'Workout log',
    description: 'Sets, reps and weight per session, with your best lift.',
    rowName: 'Set',
    icon: FaDumbbell,
    spec: {
      columns: [
        { name: 'Date', type: 'date' },
        {
          name: 'Exercise',
          type: 'select',
          options: [
            'Squat',
            'Bench press',
            'Deadlift',
            'Overhead press',
            'Row',
            'Pull-up',
            'Run',
            'Cycle',
          ],
        },
        { name: 'Sets', type: 'number' },
        { name: 'Reps', type: 'number', description: 'Per set' },
        { name: 'Weight', type: 'decimal' },
      ],
      views: [
        {
          name: 'Log',
          kind: 'table',
          sortByColumn: 'Date',
          sortDesc: true,
          derivedColumns: [
            {
              name: 'Total reps',
              kind: 'product',
              args: { a: 'Sets', b: 'Reps' },
            },
          ],
          aggregates: [
            { function: 'max', column: 'Weight' },
            { function: 'sum', column: 'Sets', row: 1 },
          ],
          // A press stamps today, so a logged set needs no date typed.
          quickAdd: {
            label: 'Log set',
            presets: [{ kind: 'setNow', column: 'Date' }],
          },
          breakdownColumn: 'Exercise',
          breakdownGranularity: 'exact',
          columnOrder: [
            'Name',
            'Date',
            'Exercise',
            'Sets',
            'Reps',
            'Total reps',
            'Weight',
          ],
          default: true,
        },
        { name: 'Calendar', kind: 'calendar', groupByColumn: 'Date' },
      ],
    },
  },
  {
    id: 'plant-care',
    title: 'Plant care',
    description: 'Last watered plus an interval works out what is due.',
    rowName: 'Plant',
    icon: FaSeedling,
    spec: {
      columns: [
        { name: 'Species', type: 'text' },
        {
          name: 'Location',
          type: 'select',
          options: [
            'Living room',
            'Kitchen',
            'Bedroom',
            'Office',
            'Bathroom',
            'Balcony',
          ],
        },
        { name: 'Last watered', type: 'date' },
        {
          name: 'Water every',
          type: 'number',
          description: 'Days between watering',
        },
        { name: 'Notes', type: 'markdown' },
      ],
      views: [
        {
          name: 'All plants',
          kind: 'table',
          // Longest unwatered first, so the top of the table is the to-do list.
          sortByColumn: 'Last watered',
          sortDesc: false,
          derivedColumns: [
            {
              name: 'Thirsty for',
              kind: 'daysSince',
              args: { from: 'Last watered' },
            },
            {
              name: 'Next water',
              kind: 'offset',
              args: { from: 'Last watered', days: 'Water every' },
            },
          ],
          columnOrder: [
            'Name',
            'Species',
            'Last watered',
            'Thirsty for',
            'Water every',
            'Next water',
            'Location',
          ],
          // The whole app in one button: you water a plant, you press Watered.
          rowActions: [
            { label: 'Watered', kind: 'setNow', column: 'Last watered' },
          ],
          quickAdd: {
            label: 'Add plant',
            field: 'Name',
            placeholder: 'Which plant?',
          },
          default: true,
        },
        { name: 'By room', kind: 'kanban', groupByColumn: 'Location' },
      ],
    },
  },
  {
    id: 'inventory',
    title: 'Inventory',
    description: 'Quantities and value per item, with a low-stock view.',
    rowName: 'Item',
    icon: FaBoxesStacked,
    spec: {
      columns: [
        { name: 'Quantity', type: 'number' },
        { name: 'Unit price', type: 'decimal' },
        {
          name: 'Category',
          type: 'select',
          options: [
            'Electronics',
            'Furniture',
            'Supplies',
            'Tools',
            'Stock',
            'Other',
          ],
        },
        { name: 'Location', type: 'text' },
        { name: 'SKU', type: 'text' },
      ],
      views: [
        {
          name: 'Stock',
          kind: 'table',
          derivedColumns: [
            {
              name: 'Value',
              kind: 'product',
              args: { a: 'Quantity', b: 'Unit price' },
            },
          ],
          aggregates: [{ function: 'sum', column: 'Quantity' }],
          breakdownColumn: 'Category',
          breakdownGranularity: 'exact',
          columnOrder: [
            'Name',
            'SKU',
            'Quantity',
            'Unit price',
            'Value',
            'Category',
            'Location',
          ],
          // Ids spelled out: "+1" and "-1" both slug to "1", so the labels
          // alone would collide.
          rowActions: [
            {
              id: 'plus',
              label: '+1',
              kind: 'increment',
              column: 'Quantity',
              value: 1,
            },
            {
              id: 'minus',
              label: '-1',
              kind: 'increment',
              column: 'Quantity',
              value: -1,
            },
          ],
          default: true,
        },
        {
          name: 'Low stock',
          kind: 'table',
          // Only counts items whose Quantity is filled in — an item with no
          // quantity yet has nothing to compare against.
          filters: [{ column: 'Quantity', operator: 'lte', value: '3' }],
          sortByColumn: 'Quantity',
          sortDesc: false,
        },
      ],
    },
  },
  {
    id: 'guest-list',
    title: 'Guest list',
    description: 'Who is coming, plus-ones included, totalled per answer.',
    rowName: 'Guest',
    icon: FaUserGroup,
    spec: {
      columns: [
        {
          name: 'RSVP',
          type: 'select',
          options: ['Invited', 'Yes', 'No', 'Maybe'],
        },
        { name: 'Plus ones', type: 'number' },
        { name: 'Email', type: 'text' },
        { name: 'Dietary needs', type: 'text' },
      ],
      views: [
        {
          name: 'Guests',
          kind: 'table',
          aggregates: [{ function: 'sum', column: 'Plus ones' }],
          breakdownColumn: 'RSVP',
          breakdownGranularity: 'exact',
          default: true,
        },
        { name: 'By answer', kind: 'kanban', groupByColumn: 'RSVP' },
      ],
    },
  },
  {
    id: 'bookmarks',
    title: 'Bookmarks',
    description: 'Links with a kind and notes, newest first.',
    rowName: 'Bookmark',
    icon: FaBookmark,
    spec: {
      columns: [
        { name: 'URL', type: 'text' },
        {
          name: 'Kind',
          type: 'select',
          options: [
            'Article',
            'Tool',
            'Video',
            'Documentation',
            'Inspiration',
            'To read',
          ],
        },
        { name: 'Added', type: 'date' },
        { name: 'Notes', type: 'markdown' },
      ],
      views: [
        {
          name: 'All bookmarks',
          kind: 'table',
          sortByColumn: 'Added',
          sortDesc: true,
          breakdownColumn: 'Kind',
          breakdownGranularity: 'exact',
          default: true,
        },
        { name: 'By kind', kind: 'kanban', groupByColumn: 'Kind' },
      ],
    },
  },
];

import React, { useEffect } from 'react';
import { ContainerFull } from '../components/Containers';
import fetch from 'cross-fetch';

const baseUrl =
  'https://www.mt-dataexchange.nl/orion/ngsi-ld/v1/entities/urn:ngsi-ld:Devices:public-eye_';
const devices = ['Boardwalk', 'Waterfront', 'MT-Picnic'];

export function I4Trust(): JSX.Element {
  const [token, setToken] = useLocalStorage('token', '');

  return (
    <main>
      <ContainerFull>
        <h1>Orion Sensor Data</h1>
        <label>
          Token
          <input value={token} onChange={e => setToken(e.target.value)} />
        </label>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          {token &&
            devices.map(device => (
              <Device id={device} key={device} token={token} />
            ))}
          {!token && <p>Enter a token</p>}
        </div>
      </ContainerFull>
    </main>
  );
}

export interface Measurement {
  id: string;
  type: string;
  refDevice: DateObserved;
  measurementType: DateObserved;
  description: DateObserved;
  numValue: NumValue;
  dateObserved: DateObserved;
}

export interface DateObserved {
  type: string;
  value: string;
}

export interface NumValue {
  type: string;
  value: number;
  observedAt: string;
  instanceId: string;
}

export interface Device {
  id: string;
  type: string;
  'https://smartdatamodels.org/dataModel.Device/category': Description;
  description: Description;
}

export interface Description {
  type: string;
  value: string;
}

export interface Temporal {
  id: string;
  numValue: NumValue[];
}

function orionFetch<T>(url: string, token: string): Promise<T> {
  const fetchOpts = {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };

  return fetch(url, fetchOpts).then(res => res.json());
}

function fetchMeasurement(id: string, token: string): Promise<Measurement> {
  const url = `${baseUrl}${id}-measurement`;

  return orionFetch(url, token);
}

function fetchDevice(id: string, token: string): Promise<Device> {
  const url = `${baseUrl}${id}`;

  return orionFetch(url, token);
}

function fetchTemporal(id: string, token: string): Promise<Temporal> {
  const url = `https://www.mt-dataexchange.nl/orion-temporal/temporal/entities/urn:ngsi-ld:Devices:public-eye_${id}-measurement?lastN=60`;

  return orionFetch(url, token);
}

function timeAgo(dateString?: string): string {
  if (!dateString) {
    return '';
  } else {
    const date = new Date(dateString);
    const now = new Date();
    now.setHours(now.getHours() + 2);
    const diff = now.getTime() - date.getTime();
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) {
      return `${days} day${days > 1 ? 's' : ''} ago`;
    } else if (hours > 0) {
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else if (minutes > 0) {
      return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else {
      return `${seconds} second${seconds > 1 ? 's' : ''} ago`;
    }
  }
}

function Device({ id, token }) {
  const [measurement, setMeasurement] = React.useState<Measurement | undefined>(
    undefined,
  );
  const [device, setDevice] = React.useState<Device | undefined>(undefined);
  const [temporal, setTemporal] = React.useState<Temporal | undefined>(
    undefined,
  );
  const [error, setError] = React.useState<Error | undefined>(undefined);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const mes = await fetchMeasurement(id, token);
        setMeasurement(mes);
        const dev = await fetchDevice(id, token);
        setDevice(dev);
        const tmp = await fetchTemporal(id, token);
        setTemporal(tmp);
      } catch (e) {
        console.error(e);
        setError(e);
      }
    };

    fetchData();
    const intervalId = setInterval(fetchData, 15000);

    return () => clearInterval(intervalId);
  }, [token]);

  if (error) {
    return <div>Error: {error.message}</div>;
  }

  return (
    <div style={{}}>
      <h2>{id}</h2>
      <p>{device?.description.value}</p>
      <p>
        Latest: <strong>{measurement?.numValue.value}</strong> (
        {timeAgo(measurement?.dateObserved.value)})
      </p>
      <Graph measurement={measurement} temporal={temporal} device={device} />
    </div>
  );
}

function showTime(dateString?: string): string {
  if (!dateString) {
    return '';
  } else {
    const date = new Date(dateString);
    const hours = date.getHours();
    const minutes = date.getMinutes();

    return `${hours}:${minutes}`;
  }
}

import {
  XYPlot,
  XAxis,
  YAxis,
  VerticalGridLines,
  HorizontalGridLines,
  LineMarkSeries,
} from 'react-vis';
import { useLocalStorage } from '@tomic/react';

export default function Graph(props) {
  const coordinates = props.temporal?.numValue.map((value, _index) => {
    return { x: new Date(value.observedAt).getTime(), y: value.value };
  });

  return (
    <XYPlot width={300} height={300}>
      <VerticalGridLines />
      <HorizontalGridLines />
      <XAxis title='time' tickFormat={v => showTime(v)} />
      <YAxis title={props.measurement?.description.value} />
      <LineMarkSeries
        className='linemark-series-example'
        style={{
          strokeWidth: '3px',
        }}
        lineStyle={{ stroke: 'blue', fill: 'none' }}
        markStyle={{ stroke: 'blue' }}
        data={coordinates}
      />
    </XYPlot>
  );
}

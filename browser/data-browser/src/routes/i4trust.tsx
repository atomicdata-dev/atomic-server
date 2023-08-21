import React, { useEffect } from 'react';
import { ContainerFull } from '../components/Containers';
import fetch from 'cross-fetch';

const baseUrl =
  'https://www.mt-dashboard.nl/orion/ngsi-ld/v1/entities/urn:ngsi-ld:Devices:public-eye_';
const devices = ['Boardwalk', 'Waterfront', 'MT-Picnic'];

export function I4Trust(): JSX.Element {
  return (
    <main>
      <ContainerFull>
        <h1>Orion Sensor Data</h1>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          {devices.map(device => (
            <Device id={device} key={device} />
          ))}
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

function fetchMeasurement(id: string): Promise<Measurement> {
  const url = `${baseUrl}${id}-measurement`;

  return fetch(url).then(res => res.json());
}

function fetchDevice(id: string): Promise<Device> {
  const url = `${baseUrl}${id}`;

  return fetch(url).then(res => res.json());
}

function fetchTemporal(id: string): Promise<Temporal> {
  const url = `https://www.mt-dashboard.nl/orion-temporal/temporal/entities/urn:ngsi-ld:Devices:public-eye_${id}-measurement?lastN=60`;

  return fetch(url).then(res => res.json());
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

function Device({ id }) {
  const [measurement, setMeasurement] = React.useState<Measurement | undefined>(
    undefined,
  );
  const [device, setDevice] = React.useState<Device | undefined>(undefined);
  const [temporal, setTemporal] = React.useState<Temporal | undefined>(
    undefined,
  );

  const fetchData = () => {
    fetchMeasurement(id).then(setMeasurement);
    fetchDevice(id).then(setDevice);
    fetchTemporal(id).then(setTemporal);
  };

  useEffect(() => {
    fetchData();
    const intervalId = setInterval(fetchData, 15000);

    return () => clearInterval(intervalId);
  }, []);

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
        lineStyle={{ stroke: 'red', fill: 'none' }}
        markStyle={{ stroke: 'blue' }}
        data={coordinates}
      />
    </XYPlot>
  );
}

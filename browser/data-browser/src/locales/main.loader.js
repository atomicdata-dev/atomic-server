import { useEffect, useState } from 'react'
import { registerLoaders } from 'wuchale/load-utils'
import { loadCatalog, loadIDs } from './.wuchale/main.proxy.js'

export const key = 'main'
/** @type {{[loadID: string]: Set<Function>}} */
const callbacks = {}
const store = {}

// non-reactive
export const getRuntime = (/** @type {string} */ loadID) => store[loadID]

const collection = {
    get: getRuntime,
    set: (/** @type {string} */ loadID, /** @type {import('wuchale/runtime').Runtime} */ runtime) => {
        store[loadID] = runtime // for when useEffect hasn't run yet
        callbacks[loadID]?.forEach((cb) => {
            cb(runtime)
        })
    },
}

registerLoaders(key, loadCatalog, loadIDs, collection)

export const getRuntimeRx = (/** @type {string} */ loadID) => {
    // function to useState because runtime is a function too
    const [runtime, setRuntime] = useState(() => getRuntime(loadID))
    useEffect(() => {
        const cb = (/** @type {import('wuchale/runtime').Runtime} */ runtime) => setRuntime(() => runtime)
        callbacks[loadID] ??= new Set()
        callbacks[loadID].add(cb)
        return () => callbacks[loadID].delete(cb)
    }, [loadID])
    return runtime
}

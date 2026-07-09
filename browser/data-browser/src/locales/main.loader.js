import { useEffect, useState } from 'react'
import { registerLoaders } from 'wuchale/load-utils'
import { loadCatalog, loadCount } from './.wuchale/main.proxy.js'

export const key = 'main'
/** @type {Set<Function>[]} */
const callbacks = []
/** @type {import('wuchale/runtime').Runtime[]} */
const store = []

// non-reactive
export const getRuntime = (loadID = 0) => /** @type {import('wuchale/runtime').Runtime} */ (store[loadID])

const collection = {
    get: getRuntime,
    set: (/** @type {number} */ loadID, /** @type {import('wuchale/runtime').Runtime} */ runtime) => {
        store[loadID] = runtime // for when useEffect hasn't run yet
        callbacks[loadID]?.forEach(cb => {
            cb(runtime)
        })
    },
}

registerLoaders(key, loadCatalog, loadCount, collection)

export const getRuntimeRx = (loadID = 0) => {
    // function to useState because runtime is a function too
    const [runtime, setRuntime] = useState(() => getRuntime(loadID))
    useEffect(() => {
        const cb = (/** @type {import('wuchale/runtime').Runtime} */ runtime) => setRuntime(() => runtime)
        callbacks[loadID] ??= new Set()
        callbacks[loadID].add(cb)
        return () => /** @type {Set<Function>} */ (callbacks[loadID]).delete(cb)
    }, [loadID])
    return runtime
}

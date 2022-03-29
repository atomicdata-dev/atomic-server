// ============================================= //
// WebAssembly runtime for TypeScript            //
//                                               //
// This file is generated. PLEASE DO NOT MODIFY. //
// ============================================= //

import { encode, decode } from "@msgpack/msgpack";

import type {
    Body,
    ComplexAlias,
    ComplexGuestToHost,
    ComplexHostToGuest,
    ExplicitedlyImportedType,
    FloatingPoint,
    GroupImportedType1,
    GroupImportedType2,
    HttpRequestOptions,
    Point,
    RequestError,
    RequestMethod,
    RequestOptions,
    Response,
    Result,
    Simple,
    Value,
} from "./types";

type FatPtr = bigint;

export type Imports = {
    countWords: (string: string) => Result<number, string>;
    log: (message: string) => void;
    makeRequest: (opts: RequestOptions) => Promise<Result<Response, RequestError>>;
    myAsyncImportedFunction: () => Promise<ComplexHostToGuest>;
    myComplexImportedFunction: (a: ComplexAlias) => ComplexHostToGuest;
    myPlainImportedFunction: (a: number, b: number) => number;
};

export type Exports = {
    fetchData?: (url: string) => Promise<string>;
    myAsyncExportedFunction?: () => Promise<ComplexGuestToHost>;
    myComplexExportedFunction?: (a: ComplexHostToGuest) => ComplexAlias;
    myPlainExportedFunction?: (a: number, b: number) => number;
    fetchDataRaw?: (url: Uint8Array) => Promise<Uint8Array>;
    myAsyncExportedFunctionRaw?: () => Promise<Uint8Array>;
    myComplexExportedFunctionRaw?: (a: Uint8Array) => Uint8Array;
};

/**
 * Represents an unrecoverable error in the FP runtime.
 *
 * After this, your only recourse is to create a new runtime, probably with a different WASM plugin.
 */
export class FPRuntimeError extends Error {
    constructor(message: string) {
        super(message);
    }
}

/**
 * Creates a runtime for executing the given plugin.
 *
 * @param plugin The raw WASM plugin.
 * @param importFunctions The host functions that may be imported by the plugin.
 * @returns The functions that may be exported by the plugin.
 */
export async function createRuntime(
    plugin: ArrayBuffer,
    importFunctions: Imports
): Promise<Exports> {
    const promises = new Map<FatPtr, (result: FatPtr) => void>();

    function createAsyncValue(): FatPtr {
        const len = 12; // std::mem::size_of::<AsyncValue>()
        const fatPtr = malloc(len);
        const [ptr] = fromFatPtr(fatPtr);
        const buffer = new Uint8Array(memory.buffer, ptr, len);
        buffer.fill(0);
        return fatPtr;
    }

    function parseObject<T>(fatPtr: FatPtr): T {
        const [ptr, len] = fromFatPtr(fatPtr);
        const buffer = new Uint8Array(memory.buffer, ptr, len);
        const object = decode<T>(buffer) as T;
        free(fatPtr);
        return object;
    }

    function promiseFromPtr(ptr: FatPtr): Promise<FatPtr> {
        return new Promise((resolve) => {
            promises.set(ptr, resolve as (result: FatPtr) => void);
        });
    }

    function resolvePromise(asyncValuePtr: FatPtr, resultPtr: FatPtr) {
        const resolve = promises.get(asyncValuePtr);
        if (!resolve) {
            throw new FPRuntimeError("Tried to resolve unknown promise");
        }

        resolve(resultPtr);
    }

    function serializeObject<T>(object: T): FatPtr {
        return exportToMemory(encode(object));
    }

    function exportToMemory(serialized: Uint8Array): FatPtr {
        const fatPtr = malloc(serialized.length);
        const [ptr, len] = fromFatPtr(fatPtr);
        const buffer = new Uint8Array(memory.buffer, ptr, len);
        buffer.set(serialized);
        return fatPtr;
    }

    function importFromMemory(fatPtr: FatPtr): Uint8Array {
        const [ptr, len] = fromFatPtr(fatPtr);
        const buffer = new Uint8Array(memory.buffer, ptr, len);
        const copy = new Uint8Array(len);
        copy.set(buffer);
        free(fatPtr);
        return copy;
    }

    const { instance } = await WebAssembly.instantiate(plugin, {
        fp: {
            __fp_gen_count_words: (string_ptr: FatPtr): FatPtr => {
                const string = parseObject<string>(string_ptr);
                return serializeObject(importFunctions.countWords(string));
            },
            __fp_gen_log: (message_ptr: FatPtr) => {
                const message = parseObject<string>(message_ptr);
                importFunctions.log(message);
            },
            __fp_gen_make_request: (opts_ptr: FatPtr): FatPtr => {
                const opts = parseObject<RequestOptions>(opts_ptr);
                const _async_result_ptr = createAsyncValue();
                importFunctions.makeRequest(opts)
                    .then((result) => {
                        resolveFuture(_async_result_ptr, serializeObject(result));
                    })
                    .catch((error) => {
                        console.error(
                            'Unrecoverable exception trying to call async host function "make_request"',
                            error
                        );
                    });
                return _async_result_ptr;
            },
            __fp_gen_my_async_imported_function: (): FatPtr => {
                const _async_result_ptr = createAsyncValue();
                importFunctions.myAsyncImportedFunction()
                    .then((result) => {
                        resolveFuture(_async_result_ptr, serializeObject(result));
                    })
                    .catch((error) => {
                        console.error(
                            'Unrecoverable exception trying to call async host function "my_async_imported_function"',
                            error
                        );
                    });
                return _async_result_ptr;
            },
            __fp_gen_my_complex_imported_function: (a_ptr: FatPtr): FatPtr => {
                const a = parseObject<ComplexAlias>(a_ptr);
                return serializeObject(importFunctions.myComplexImportedFunction(a));
            },
            __fp_gen_my_plain_imported_function: (a: number, b: number): number => {
                return importFunctions.myPlainImportedFunction(a, b);
            },
            __fp_host_resolve_async_value: resolvePromise,
        },
    });

    const getExport = <T>(name: string): T => {
        const exp = instance.exports[name];
        if (!exp) {
            throw new FPRuntimeError(`Plugin did not export expected symbol: "${name}"`);
        }
        return exp as unknown as T;
    };

    const memory = getExport<WebAssembly.Memory>("memory");
    const malloc = getExport<(len: number) => FatPtr>("__fp_malloc");
    const free = getExport<(ptr: FatPtr) => void>("__fp_free");
    const resolveFuture = getExport<(asyncValuePtr: FatPtr, resultPtr: FatPtr) => void>("__fp_guest_resolve_async_value");

    return {
        fetchData: (() => {
            const export_fn = instance.exports.__fp_gen_fetch_data as any;
            if (!export_fn) return;

            return (url: string) => {
                const url_ptr = serializeObject(url);
                return promiseFromPtr(export_fn(url_ptr)).then((ptr) => parseObject<string>(ptr));
            };
        })(),
        myAsyncExportedFunction: (() => {
            const export_fn = instance.exports.__fp_gen_my_async_exported_function as any;
            if (!export_fn) return;

            return () => promiseFromPtr(export_fn()).then((ptr) => parseObject<ComplexGuestToHost>(ptr));
        })(),
        myComplexExportedFunction: (() => {
            const export_fn = instance.exports.__fp_gen_my_complex_exported_function as any;
            if (!export_fn) return;

            return (a: ComplexHostToGuest) => {
                const a_ptr = serializeObject(a);
                return parseObject<ComplexAlias>(export_fn(a_ptr));
            };
        })(),
        myPlainExportedFunction: instance.exports.__fp_gen_my_plain_exported_function as any,
        fetchDataRaw: (() => {
            const export_fn = instance.exports.__fp_gen_fetch_data as any;
            if (!export_fn) return;

            return (url: Uint8Array) => {
                const url_ptr = exportToMemory(url);
                return promiseFromPtr(export_fn(url_ptr)).then(importFromMemory);
            };
        })(),
        myAsyncExportedFunctionRaw: (() => {
            const export_fn = instance.exports.__fp_gen_my_async_exported_function as any;
            if (!export_fn) return;

            return () => promiseFromPtr(export_fn()).then(importFromMemory);
        })(),
        myComplexExportedFunctionRaw: (() => {
            const export_fn = instance.exports.__fp_gen_my_complex_exported_function as any;
            if (!export_fn) return;

            return (a: Uint8Array) => {
                const a_ptr = exportToMemory(a);
                return importFromMemory(export_fn(a_ptr));
            };
        })(),
    };
}

function fromFatPtr(fatPtr: FatPtr): [ptr: number, len: number] {
    return [
        Number.parseInt((fatPtr >> 32n).toString()),
        Number.parseInt((fatPtr & 0xffff_ffffn).toString()),
    ];
}

function toFatPtr(ptr: number, len: number): FatPtr {
    return (BigInt(ptr) << 32n) | BigInt(len);
}

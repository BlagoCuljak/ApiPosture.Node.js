import { Endpoint } from '../models/endpoint.js';
import { LoadedSourceFile } from '../analysis/source-file-loader.js';

export interface EndpointDiscoverer {
  readonly name: string;
  discover(file: LoadedSourceFile): Promise<Endpoint[]>;
}

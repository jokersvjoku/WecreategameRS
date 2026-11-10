import ResultsView from "@/components/views/ResultsView";

export function generateStaticParams() {
  return [{ id: "demo" }, { id: "latest" }, { id: "sample" }];
}

export default function Page() {
  return <ResultsView />;
}
